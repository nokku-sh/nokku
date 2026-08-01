package daemon

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/meta"
)

func (p *Pool) Connect(
	ctx context.Context,
	stream *connect.BidiStream[nokkuv1.ConnectRequest, nokkuv1.ConnectResponse],
) error {
	daemonID := meta.DaemonIDFromContext(ctx)
	if daemonID == "" {
		return connect.NewError(
			connect.CodePermissionDenied,
			errors.New("daemon authentication required"),
		)
	}

	daemon, err := p.conn.Q.GetDaemon(ctx, daemonID)
	if err != nil {
		return connect.NewError(connect.CodeNotFound, errors.New("daemon not found"))
	}
	if daemon.Status != nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED {
		return connect.NewError(connect.CodePermissionDenied, errors.New("daemon not accepted"))
	}

	conn := p.RegisterDaemon(ctx, daemonID, daemon.WorkspaceID)
	defer p.UnregisterDaemon(daemonID, conn)

	// Outbound: drain the daemon's send channel to the stream
	go func() {
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
			}
		}
	}()

	// Inbound: heartbeats/sync from the daemon
	recvErr := make(chan error, 1)
	go func() {
		for {
			if _, err := stream.Receive(); err != nil {
				recvErr <- err
				return
			}
		}
	}()

	select {
	case <-conn.ctx.Done():
		return conn.ctx.Err()
	case err := <-recvErr:
		return err
	}
}

func (p *Pool) Session(
	ctx context.Context,
	stream *connect.BidiStream[nokkuv1.SessionRequest, nokkuv1.SessionResponse],
) error {
	daemonID := meta.DaemonIDFromContext(ctx)
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
	ready, ok := msg.GetMsg().(*nokkuv1.SessionRequest_Ready)
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

	// Outbound: stdin/resize/close from browsers to the daemon stream
	go func() {
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
			case *nokkuv1.SessionRequest_Stdout:
				sess.AppendStdout(m.Stdout)

			case *nokkuv1.SessionRequest_Exited:
				recvErr <- nil
				return

			default:
			}
		}
	}()

	select {
	case <-sess.Exited:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case err := <-recvErr:
		return err
	}
}
