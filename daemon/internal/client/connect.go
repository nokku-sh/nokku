package client

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"connectrpc.com/connect"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
)

// Proxies close a stream idle for 60s, and the core drops one silent for 2 minutes.
const heartbeatInterval = 30 * time.Second

type controlStream = connect.BidiStreamForClientSimple[nokkuv1.ConnectRequest, nokkuv1.ConnectResponse]

// Only a daemon rejection is fatal to the caller.
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
			// Relays get ctx, not streamCtx, so a stream reconnect does not cut live web sessions.
			c.relays.Go(func() { c.runRelay(ctx, m.RelayOpen) })
		}
	}
}

func (c *Client) sendHeartbeats(ctx context.Context, stream *controlStream) {
	t := time.NewTicker(heartbeatInterval)
	defer t.Stop()
	for {
		version := c.cache.GetStateVersion()
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
