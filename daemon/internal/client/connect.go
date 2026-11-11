package client

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/nokku-sh/nokku/daemon/internal/report"
	"github.com/nokku-sh/nokku/daemon/internal/safe"

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
	// Per stream, so an ack never counts for a report an earlier stream sent.
	acked := make(chan struct{}, 1)
	go c.send(streamCtx, stream, acked)

	for {
		msg, recvErr := stream.Receive()
		if recvErr != nil {
			return recvErr
		}
		switch m := msg.GetMsg().(type) {
		case *nokkuv1.ConnectResponse_ConnectionReportAck:
			select {
			case acked <- struct{}{}:
			default:
			}
		case *nokkuv1.ConnectResponse_StateUpdate:
			// The core says what this daemon should hold. With that on disk already there is nothing to fetch.
			if want := m.StateUpdate.GetStateHash(); len(want) > 0 && bytes.Equal(want, c.state.Saved().StateHash) {
				continue
			}
			err = c.syncDaemon(ctx)
			if errors.Is(err, errDaemonRejected) {
				return err
			}
			if err != nil {
				slog.Warn("sync after state update failed", "error", err)
			}
		case *nokkuv1.ConnectResponse_RelayOpen:
			// Not streamCtx, a stream reconnect must not cut live sessions.
			c.relays.Go(safe.Func("relay", func() { c.runRelay(ctx, m.RelayOpen) }))
		}
	}
}

// send is the stream's only writer. It sends a heartbeat on every tick and the spooled connection reports, one at
// a time. A report stays in the spool until the core acks it, so a stream that dies takes none along.
func (c *Client) send(
	ctx context.Context,
	stream nokkuv1connect.DaemonControlServiceConnectClientStream,
	acked <-chan struct{},
) {
	// HTTP/2 only sees a cancel once the body ends. Until then the read waits,
	// and the core takes two minutes to drop a silent daemon.
	defer func() { _ = stream.CloseSend() }()
	t := time.NewTicker(heartbeatInterval)
	defer t.Stop()
	heartbeat := func() error {
		return stream.Send(&nokkuv1.ConnectRequest{
			Msg: &nokkuv1.ConnectRequest_Heartbeat{Heartbeat: &nokkuv1.Heartbeat{StateHash: c.state.Saved().StateHash}},
		})
	}
	if heartbeat() != nil {
		return
	}
	// sent is what the core has and did not ack yet. look says the spool may hold something to send, as it may
	// from an earlier stream or an earlier run.
	var sent int
	var sentDropped uint32
	look := true
	for {
		if look && sent == 0 {
			look = false
			events, dropped := c.reports.Next()
			if len(events) > 0 {
				if stream.Send(connectionReport(events, dropped)) != nil {
					return
				}
				sent, sentDropped = len(events), dropped
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if heartbeat() != nil {
				return
			}
		case <-c.reports.Ready():
			look = true
		case <-acked:
			c.reports.Done(sent, sentDropped)
			sent, sentDropped, look = 0, 0, true
		}
	}
}

func connectionReport(events []report.Event, dropped uint32) *nokkuv1.ConnectRequest {
	r := &nokkuv1.ConnectionReport{Dropped: &dropped}
	// A string the wire cannot carry fails the send, and its event would come first in every report after.
	wire := func(s string) *string { return new(strings.ToValidUTF8(s, "")) }
	for _, e := range events {
		r.Events = append(r.Events, &nokkuv1.ConnectionEvent{
			ConnectionId:  &e.ConnectionID,
			Closed:        &e.Closed,
			Time:          timestamppb.New(e.Time),
			Principal:     wire(e.Principal),
			KeyId:         wire(e.KeyID),
			RemoteAddr:    wire(e.Remote),
			ClientVersion: wire(e.Client),
			Relayed:       &e.Relayed,
		})
	}
	return &nokkuv1.ConnectRequest{Msg: &nokkuv1.ConnectRequest_ConnectionReport{ConnectionReport: r}}
}
