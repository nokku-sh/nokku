package daemon

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/iam"
)

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

	// Inbound: heartbeats carry the daemon's state version. Any mismatch
	// with the workspace counter gets an ack so the daemon re-syncs: a
	// daemon that is behind catches up, and after a server restart the
	// counter starts over at 0, so every daemon re-syncs once and no change
	// committed while it was disconnected can be missed.
	recvErr := make(chan error, 1)
	go func() {
		for {
			req, err := stream.Receive()
			if err != nil {
				recvErr <- err
				return
			}
			if hb, ok := req.GetMsg().(*nokkuv1.ConnectRequest_Heartbeat); ok {
				if version, ack := p.HeartbeatVersion(
					daemonID,
					hb.Heartbeat.GetStateVersion(),
				); ack {
					p.sendStateUpdate(conn, &nokkuv1.ConnectResponse{
						Msg: &nokkuv1.ConnectResponse_HeartbeatAck{
							HeartbeatAck: &nokkuv1.HeartbeatAck{StateVersion: &version},
						},
					})
				}
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

func (p *Pool) DaemonSession(
	ctx context.Context,
	stream *connect.BidiStream[nokkuv1.DaemonSessionRequest, nokkuv1.DaemonSessionResponse],
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
	ready, ok := msg.GetMsg().(*nokkuv1.DaemonSessionRequest_Ready)
	if !ok || ready.Ready == nil {
		return connect.NewError(
			connect.CodeInvalidArgument,
			errors.New("first message must be SessionReady"),
		)
	}

	sessionID := ready.Ready.GetSessionId()
	if sessionID == "" {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("session_id required"))
	}

	// Cancelling on return guarantees both directions unwind even on a
	// send/receive error.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sess := p.RegisterSession(
		sessionID,
		daemonID,
		ready.Ready.GetUsername(),
		ready.Ready.GetUserId(),
	)
	defer p.UnregisterSession(sessionID)
	defer sess.shutdown()

	// Outbound: stdin/resize/close from browsers to the daemon stream.
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
			case m, ok := <-sess.send:
				if !ok {
					return
				}
				if err := stream.Send(m); err != nil {
					return
				}
			}
		}
	}()

	// Inbound: PTY stdout / exit from the daemon
	recvErr := make(chan error, 1)
	go func() {
		for {
			msg, err := stream.Receive()
			if err != nil {
				recvErr <- err
				return
			}

			switch m := msg.GetMsg().(type) {
			case *nokkuv1.DaemonSessionRequest_Stdout:
				sess.AppendStdout(m.Stdout)

			case *nokkuv1.DaemonSessionRequest_Exited:
				recvErr <- nil
				return

			default:
			}
		}
	}()

	var retErr error
	select {
	case <-sess.Exited:
	case <-ctx.Done():
		retErr = ctx.Err()
	case err := <-recvErr:
		retErr = err
	}
	// The deferred cancel only runs at return; stop the pump now so the
	// join below cannot deadlock if the peer stopped reading.
	cancel()
	<-outDone
	return retErr
}
