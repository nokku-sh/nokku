package daemon

import (
	"context"
	"errors"
	"io"

	"connectrpc.com/connect"
	"golang.org/x/time/rate"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
)

const (
	relayBandwidth = 32 << 20 // bytes/s per direction
	relayBurst     = 1 << 20
)

// waitRelayBytes steps in burst-sized chunks since WaitN rejects larger ones.
func waitRelayBytes(ctx context.Context, l *rate.Limiter, n int) error {
	for n > relayBurst {
		if err := l.WaitN(ctx, relayBurst); err != nil {
			return err
		}
		n -= relayBurst
	}
	return l.WaitN(ctx, n)
}

// BridgeRelay is a dumb pipe, the SSH session inside is end-to-end encrypted.
func BridgeRelay(
	ctx context.Context,
	stream *connect.BidiStream[nokkuv1.RelayRequest, nokkuv1.RelayResponse],
	relay *Relay,
) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// One bucket per direction so heavy traffic one way can't starve the other.
	outLimiter := rate.NewLimiter(relayBandwidth, relayBurst)
	inLimiter := rate.NewLimiter(relayBandwidth, relayBurst)

	outDone := make(chan struct{})
	go func() {
		defer close(outDone)
		defer cancel()
		for {
			select {
			case <-ctx.Done():
				return
			case data := <-relay.ToUser:
				if err := waitRelayBytes(ctx, outLimiter, len(data)); err != nil {
					relay.Close()
					return
				}
				if err := stream.Send(&nokkuv1.RelayResponse{
					Msg: &nokkuv1.RelayResponse_Data{Data: data},
				}); err != nil {
					relay.Close()
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
				relay.Close()
				return
			}
			if data, ok := msg.GetMsg().(*nokkuv1.RelayRequest_Data); ok {
				if err := waitRelayBytes(ctx, inLimiter, len(data.Data)); err != nil {
					recvErr <- err
					relay.Close()
					return
				}
				select {
				case relay.ToDaemon <- data.Data:
				case <-relay.Done():
					return
				}
			}
		}
	}()

	var retErr error
	select {
	case <-relay.Done():
	case err := <-recvErr:
		if !errors.Is(err, io.EOF) {
			retErr = err
		}
	}
	// Stop the pump now so the join cannot deadlock on a peer that stopped reading.
	cancel()
	<-outDone
	// Best effort, so the peer never waits on a wedged half.
	_ = stream.Send(&nokkuv1.RelayResponse{
		Msg: &nokkuv1.RelayResponse_Closed{Closed: &nokkuv1.RelayClosed{}},
	})
	return retErr
}
