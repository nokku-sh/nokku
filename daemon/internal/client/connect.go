package client

import (
	"context"
	"errors"
	"log/slog"
	"time"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"
)

// Proxies close streams idle for 60s, the core drops ones silent for 2 minutes.
const heartbeatInterval = 30 * time.Second

func (c *Client) runControlStream(ctx context.Context) error {
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := c.ctl.Connect(streamCtx)
	if err != nil {
		return err
	}
	go c.sendHeartbeats(streamCtx, stream)

	for {
		msg, recvErr := stream.Receive()
		if recvErr != nil {
			return recvErr
		}
		switch m := msg.GetMsg().(type) {
		case *nokkuv1.ConnectResponse_StateUpdate:
			err = c.syncDaemon(ctx)
			if errors.Is(err, errDaemonRejected) {
				return err
			}
			if err != nil {
				slog.Warn("sync after state update failed", "error", err)
			}
		case *nokkuv1.ConnectResponse_RelayOpen:
			// Not streamCtx, a stream reconnect must not cut live sessions.
			c.relays.Go(func() { c.runRelay(ctx, m.RelayOpen) })
		}
	}
}

func (c *Client) sendHeartbeats(ctx context.Context, stream nokkuv1connect.DaemonControlServiceConnectClientStream) {
	t := time.NewTicker(heartbeatInterval)
	defer t.Stop()
	for {
		version := c.state.SavedVersion()
		err := stream.Send(&nokkuv1.ConnectRequest{
			Msg: &nokkuv1.ConnectRequest_Heartbeat{Heartbeat: &nokkuv1.Heartbeat{StateVersion: &version}},
		})
		if err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
