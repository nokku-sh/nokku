package client

import (
	"context"
	"errors"
	"fmt"
	"io"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/cli/internal/state"
)

// Read and Write each have exactly one caller, the ProxyCommand pipes.
type relayStream struct {
	stream  nokkuv1connect.DaemonServiceRelayClientStream
	pending []byte
}

// Relay carries the raw bytes between the local ssh and the daemon's sshd.
func (c *Client) Relay(ctx context.Context, target *state.Target) (io.ReadWriteCloser, error) {
	if target.DaemonID == "" {
		return nil, fmt.Errorf("target %s is not backed by a daemon", target.Name)
	}

	stream, err := c.daemons.Relay(ctx)
	if err != nil {
		return nil, fmt.Errorf("open relay stream: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = stream.CloseSend()
			_ = stream.Close()
		}
	}()

	if err = stream.Send(&nokkuv1.RelayRequest{
		Msg: &nokkuv1.RelayRequest_Start{Start: &nokkuv1.RelayStart{
			DaemonId: new(target.DaemonID),
		}},
	}); err != nil {
		return nil, fmt.Errorf("relay start: %w", err)
	}

	res, err := stream.Receive()
	if err != nil {
		return nil, fmt.Errorf("relay ready: %w", err)
	}
	if res.GetReady() == nil {
		return nil, fmt.Errorf("unexpected relay response %T", res.GetMsg())
	}
	ok = true
	return &relayStream{stream: stream}, nil
}

func (r *relayStream) Read(p []byte) (int, error) {
	if len(r.pending) > 0 {
		n := copy(p, r.pending)
		r.pending = r.pending[n:]
		return n, nil
	}

	res, err := r.stream.Receive()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return 0, io.EOF
		}
		return 0, fmt.Errorf("relay receive: %w", err)
	}
	switch m := res.GetMsg().(type) {
	case *nokkuv1.RelayResponse_Closed:
		return 0, io.EOF
	case *nokkuv1.RelayResponse_Data:
		// A message can be larger than p, keep the rest for the next Read.
		n := copy(p, m.Data)
		r.pending = m.Data[n:]
		return n, nil
	default:
		return 0, fmt.Errorf("unexpected relay message %T", res.GetMsg())
	}
}

func (r *relayStream) Write(p []byte) (int, error) {
	// Send marshals synchronously, so p is not retained by the stream.
	if err := r.stream.Send(&nokkuv1.RelayRequest{
		Msg: &nokkuv1.RelayRequest_Data{Data: p},
	}); err != nil {
		return 0, fmt.Errorf("relay send: %w", err)
	}
	return len(p), nil
}

// Half-closes the send side. The sshd side keeps streaming until it closes the session.
func (r *relayStream) CloseWrite() error {
	return r.stream.CloseSend()
}

func (r *relayStream) Close() error {
	_ = r.stream.CloseSend()
	return r.stream.Close()
}
