package daemon

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
)

const (
	maxRelaysPerPrincipal = 64
	relayBufferSize       = 16
	pendingSessionTimeout = 10 * time.Second
)

var (
	ErrRelayLimit       = errors.New("relay limit reached")
	errRelayUnavailable = errors.New("relay unavailable")
)

// Relay bridges the daemon's DaemonRelay stream and the user's Relay stream.
type Relay struct {
	daemonID string
	userID   string
	// shell is set once a browser terminal finished its dial over the relay.
	shell *Session

	toDaemon chan []byte
	toUser   chan []byte

	closed    chan struct{}
	closeOnce sync.Once
}

type relayPending struct {
	ready    chan struct{}
	daemonID string
	userID   string
}

func (r *Relay) done() <-chan struct{} { return r.closed }

func (r *Relay) close() {
	r.closeOnce.Do(func() { close(r.closed) })
}

// RequestRelay counts the user's waiting and bridged relays against the cap.
func (p *Pool) RequestRelay(
	ctx context.Context,
	daemonID, relayID, userID, clientAddr string,
) (*Relay, error) {
	pend := &relayPending{ready: make(chan struct{}), daemonID: daemonID, userID: userID}
	p.mu.Lock()
	held := 0
	for _, other := range p.pendingRelays {
		if other.userID == userID {
			held++
		}
	}
	for _, r := range p.relays {
		if r.userID == userID {
			held++
		}
	}
	if held >= maxRelaysPerPrincipal {
		p.mu.Unlock()
		return nil, ErrRelayLimit
	}
	p.pendingRelays[relayID] = pend
	p.mu.Unlock()

	err := p.sendToDaemonWait(ctx, daemonID, &nokkuv1.ConnectResponse{
		Msg: &nokkuv1.ConnectResponse_RelayOpen{
			RelayOpen: &nokkuv1.RelayOpen{RelayId: &relayID, ClientAddr: &clientAddr},
		},
	}, 5*time.Second)
	if err == nil {
		select {
		case <-pend.ready:
		case <-time.After(pendingSessionTimeout):
			err = errors.New("relay request timed out")
		case <-ctx.Done():
			err = ctx.Err()
		}
	}

	// One lock, so a relay registering as the wait gives up is still ours.
	p.mu.Lock()
	// A newer request for the same relayID may have replaced ours.
	if p.pendingRelays[relayID] == pend {
		delete(p.pendingRelays, relayID)
	}
	r := p.relays[relayID]
	p.mu.Unlock()
	if r == nil {
		if err == nil {
			err = errors.New("relay closed before it was bridged")
		}
		return nil, fmt.Errorf("%w: %w", errRelayUnavailable, err)
	}
	return r, nil
}

// registerRelay refuses a daemon that was not asked, a rogue cannot claim one.
func (p *Pool) registerRelay(relayID, daemonID string) *Relay {
	p.mu.Lock()
	pend, ok := p.pendingRelays[relayID]
	if !ok {
		p.mu.Unlock()
		return nil
	}
	if pend.daemonID != daemonID {
		p.mu.Unlock()
		return nil
	}
	delete(p.pendingRelays, relayID)
	r := &Relay{
		daemonID: daemonID,
		userID:   pend.userID,
		toDaemon: make(chan []byte, relayBufferSize),
		toUser:   make(chan []byte, relayBufferSize),
		closed:   make(chan struct{}),
	}
	p.relays[relayID] = r
	close(pend.ready)
	p.mu.Unlock()
	return r
}

func (p *Pool) UnregisterRelay(relayID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if r := p.relays[relayID]; r != nil {
		delete(p.relays, relayID)
		r.close()
	}
}
