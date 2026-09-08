package daemon

import (
	"context"
	"errors"
	"io"

	"connectrpc.com/connect"
	"golang.org/x/time/rate"

	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
)

const (
	// Bytes per second per relay direction.
	relayBandwidth = 32 << 20
	relayBurst     = 1 << 20
)

// waitRelayBytes drains the bucket in burst-sized steps, since WaitN
// rejects requests larger than the burst.
func waitRelayBytes(ctx context.Context, l *rate.Limiter, n int) error {
	for n > relayBurst {
		if err := l.WaitN(ctx, relayBurst); err != nil {
			return err
		}
		n -= relayBurst
	}
	return l.WaitN(ctx, n)
}

// BridgeRelay pumps bytes between the user's stream and the daemon side
// until either closes. The relay is a dumb pipe: the SSH session inside is
// end-to-end encrypted between the user's client and the daemon's sshd.
func BridgeRelay(
	ctx context.Context,
	stream *connect.BidiStream[nokkuv1.RelayRequest, nokkuv1.RelayResponse],
	relay *Relay,
) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// One bucket per direction: rsync-heavy traffic one way must not starve
	// the other.
	outLimiter := rate.NewLimiter(relayBandwidth, relayBurst)
	inLimiter := rate.NewLimiter(relayBandwidth, relayBurst)

	// Outbound: daemon bytes to the user.
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

	// Inbound: user bytes to the daemon. A clean client hangup (EOF) ends
	// the relay without an error.
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
	// The deferred cancel only runs at return. Stop the pump now so the
	// join below cannot deadlock if the peer stopped reading.
	cancel()
	<-outDone
	// Best-effort closed notices so the peer never waits on a wedged half.
	_ = stream.Send(&nokkuv1.RelayResponse{
		Msg: &nokkuv1.RelayResponse_Closed{Closed: &nokkuv1.RelayClosed{}},
	})
	return retErr
}
