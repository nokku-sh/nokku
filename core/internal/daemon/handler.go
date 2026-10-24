package daemon

import (
	"context"
	"log/slog"
	"time"

	"connectrpc.com/connect/v2"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/db"
)

// heartbeatDeadline allows three missed 30s heartbeats.
const heartbeatDeadline = 2 * time.Minute

func (p *Pool) Connect(
	ctx context.Context,
	stream nokkuv1connect.DaemonControlServiceConnectServerStream,
) error {
	daemonID := actor.DaemonIDFromContext(ctx)
	if daemonID == "" {
		return connect.NewError(
			connect.CodePermissionDenied,
			"daemon authentication required",
		)
	}

	// System tx since the workspace is unknown until the daemon is looked up.
	var daemon *db.Daemon
	if err := p.conn.SysTx(ctx, func(q *db.Queries) (err error) {
		daemon, err = q.GetDaemon(ctx, daemonID)
		return err
	}); err != nil {
		return connect.NewError(connect.CodeNotFound, "daemon not found")
	}
	if daemon.Status != nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED {
		return connect.NewError(connect.CodePermissionDenied, "daemon not accepted")
	}

	conn := p.registerDaemon(ctx, daemonID, daemon.WorkspaceID)
	defer p.unregisterDaemon(daemonID, conn)

	// The handler must join outDone, a Send after ServeHTTP returns panics and kills the process.
	outDone := make(chan struct{})
	go func() {
		defer close(outDone)
		for {
			select {
			case <-conn.ctx.Done():
				return
			case msg, ok := <-conn.send:
				if !ok {
					return
				}
				if err := stream.Send(msg); err != nil {
					return
				}
			case msg, ok := <-conn.state:
				if !ok {
					return
				}
				if err := stream.Send(msg); err != nil {
					return
				}
			}
		}
	}()

	// Silence drops half-open connections. A heartbeat with a stale state version gets a StateUpdate.
	silence := time.AfterFunc(heartbeatDeadline, conn.cancel)
	defer silence.Stop()
	recvErr := make(chan error, 1)
	go func() {
		for {
			req, err := stream.Receive()
			if err != nil {
				recvErr <- err
				return
			}
			silence.Reset(heartbeatDeadline)
			hb := req.GetHeartbeat()
			if hb == nil {
				continue
			}
			version, err := p.stateVersion(conn.ctx, daemon.WorkspaceID)
			if err != nil {
				slog.Warn("read workspace state version", "daemon_id", daemonID, "error", err)
				continue
			}
			if version != hb.GetStateVersion() {
				conn.poke()
			}
		}
	}()

	var retErr error
	select {
	case <-conn.ctx.Done():
		retErr = conn.ctx.Err()
	case err := <-recvErr:
		retErr = err
	}
	// Stop the pump before joining it. The receive goroutine may outlive the handler, it only reads the body.
	conn.cancel()
	<-outDone
	return retErr
}

func (p *Pool) DaemonRelay(
	ctx context.Context,
	stream nokkuv1connect.DaemonControlServiceDaemonRelayServerStream,
) error {
	daemonID := actor.DaemonIDFromContext(ctx)
	if daemonID == "" {
		return connect.NewError(
			connect.CodePermissionDenied,
			"daemon authentication required",
		)
	}

	msg, err := stream.Receive()
	if err != nil {
		return err
	}
	ready, ok := msg.GetMsg().(*nokkuv1.DaemonRelayRequest_Ready)
	if !ok || ready.Ready == nil {
		return connect.NewError(
			connect.CodeInvalidArgument,
			"first message must be DaemonRelayReady",
		)
	}
	relayID := ready.Ready.GetRelayId()
	if relayID == "" {
		return connect.NewError(connect.CodeInvalidArgument, "relay_id required")
	}

	relay := p.registerRelay(relayID, daemonID)
	if relay == nil {
		return connect.NewError(connect.CodeInvalidArgument, "unknown relay")
	}
	defer p.UnregisterRelay(relayID)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Joined below, a Send after the handler returns kills the process.
	outDone := make(chan struct{})
	go func() {
		defer close(outDone)
		defer cancel()
		for {
			select {
			case <-ctx.Done():
				return
			case data := <-relay.toDaemon:
				if err := stream.Send(&nokkuv1.DaemonRelayResponse{
					Msg: &nokkuv1.DaemonRelayResponse_Data{Data: data},
				}); err != nil {
					relay.close()
					return
				}
			}
		}
	}()

	recvErr := make(chan error, 1)
	go func() {
		for {
			msg, err := stream.Receive()
			if err != nil {
				recvErr <- err
				relay.close()
				return
			}
			switch m := msg.GetMsg().(type) {
			case *nokkuv1.DaemonRelayRequest_Data:
				select {
				case relay.toUser <- m.Data:
				case <-relay.done():
					return
				}

			case *nokkuv1.DaemonRelayRequest_Closed:
				recvErr <- nil
				relay.close()
				return

			default:
			}
		}
	}()

	var retErr error
	select {
	case <-relay.done():
	case <-ctx.Done():
		retErr = ctx.Err()
	case err := <-recvErr:
		retErr = err
	}
	cancel()
	<-outDone
	// Best effort, so the daemon tears down its sshd dial even if it stopped reading.
	_ = stream.Send(&nokkuv1.DaemonRelayResponse{
		Msg: &nokkuv1.DaemonRelayResponse_Closed{Closed: &nokkuv1.DaemonRelayClosed{}},
	})
	return retErr
}
