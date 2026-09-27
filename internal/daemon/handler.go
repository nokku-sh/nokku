package daemon

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"connectrpc.com/connect"

	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/iam"
)

// heartbeatDeadline drops a control stream that has been silent for this
// long. Daemons heartbeat every 30s, so this allows three missed beats.
const heartbeatDeadline = 2 * time.Minute

func (p *Pool) Connect(
	ctx context.Context,
	stream *connect.BidiStream[nokkuv1.ConnectRequest, nokkuv1.ConnectResponse],
) error {
	daemonID := iam.DaemonIDFromContext(ctx)
	if daemonID == "" {
		return connect.NewError(
			connect.CodePermissionDenied,
			errors.New("daemon authentication required"),
		)
	}

	// The workspace is unknown until the daemon is looked up, so this
	// cross-tenant read runs as a system transaction (bypassing RLS).
	var daemon *db.Daemon
	if err := p.conn.WithTx(ctx, func(q *db.Queries) (err error) {
		daemon, err = q.GetDaemon(ctx, daemonID)
		return err
	}); err != nil {
		return connect.NewError(connect.CodeNotFound, errors.New("daemon not found"))
	}
	if daemon.Status != nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED {
		return connect.NewError(connect.CodePermissionDenied, errors.New("daemon not accepted"))
	}

	conn := p.RegisterDaemon(ctx, daemonID, daemon.WorkspaceID)
	defer p.UnregisterDaemon(daemonID, conn)

	// Outbound: drain the daemon's session and state channels to the stream.
	// outDone is closed once the pump stops; the handler must wait for it
	// before returning, because a Send that lands after ServeHTTP returns
	// panics ("Write called after Handler finished") and, running on this
	// spawned goroutine, that panic is unrecovered and kills the process.
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

	// Inbound: heartbeats carry the daemon's state version. A mismatch gets
	// a StateUpdate, so a daemon that missed a push while disconnected
	// catches up on its first heartbeat. A daemon that stops sending is
	// dropped, so a half-open connection cannot stay online.
	silence := time.AfterFunc(heartbeatDeadline, conn.Cancel)
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
	// UnregisterDaemon (deferred) cancels conn.ctx only after we return, so
	// stop the pump here before joining it. Receive goroutines may outlive
	// the handler briefly; they only read the request body, which is safe.
	conn.Cancel()
	<-outDone
	return retErr
}

func (p *Pool) DaemonRelay(
	ctx context.Context,
	stream *connect.BidiStream[nokkuv1.DaemonRelayRequest, nokkuv1.DaemonRelayResponse],
) error {
	daemonID := iam.DaemonIDFromContext(ctx)
	if daemonID == "" {
		return connect.NewError(
			connect.CodePermissionDenied,
			errors.New("daemon authentication required"),
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
			errors.New("first message must be DaemonRelayReady"),
		)
	}
	relayID := ready.Ready.GetRelayId()
	if relayID == "" {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("relay_id required"))
	}

	relay := p.RegisterRelay(relayID, daemonID)
	if relay == nil {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("unknown relay"))
	}
	defer p.UnregisterRelay(relayID)

	// Cancelling on return guarantees both directions unwind even on a
	// send/receive error.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Outbound: user bytes to the daemon stream.
	// Joined below: a Send landing after this handler returns panics in
	// net/http, and on a spawned goroutine that panic kills the process.
	outDone := make(chan struct{})
	go func() {
		defer close(outDone)
		defer cancel()
		for {
			select {
			case <-ctx.Done():
				return
			case data := <-relay.ToDaemon:
				if err := stream.Send(&nokkuv1.DaemonRelayResponse{
					Msg: &nokkuv1.DaemonRelayResponse_Data{Data: data},
				}); err != nil {
					relay.Close()
					return
				}
			}
		}
	}()

	// Inbound: sshd bytes from the daemon, or an explicit close.
	recvErr := make(chan error, 1)
	go func() {
		for {
			msg, err := stream.Receive()
			if err != nil {
				recvErr <- err
				relay.Close()
				return
			}
			switch m := msg.GetMsg().(type) {
			case *nokkuv1.DaemonRelayRequest_Data:
				select {
				case relay.ToUser <- m.Data:
				case <-relay.Done():
					return
				}

			case *nokkuv1.DaemonRelayRequest_Closed:
				recvErr <- nil
				relay.Close()
				return

			default:
			}
		}
	}()

	var retErr error
	select {
	case <-relay.Done():
	case <-ctx.Done():
		retErr = ctx.Err()
	case err := <-recvErr:
		retErr = err
	}
	cancel()
	<-outDone
	// Best-effort closed notice so the daemon tears down its sshd dial even
	// when it stopped reading.
	_ = stream.Send(&nokkuv1.DaemonRelayResponse{
		Msg: &nokkuv1.DaemonRelayResponse_Closed{Closed: &nokkuv1.DaemonRelayClosed{}},
	})
	return retErr
}
