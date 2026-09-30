package daemon

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
)

const (
	maxRelaysPerPrincipal = 64
	relayBufferSize       = 16
	pendingSessionTimeout = 10 * time.Second
)

var (
	ErrRelayLimit       = errors.New("relay limit reached")
	ErrRelayUnavailable = errors.New("relay unavailable")
	ErrCAInactive       = errors.New("certificate authority is not active")
)

// Relay bridges the daemon's DaemonRelay stream and the user's Relay stream.
type Relay struct {
	relayID  string
	daemonID string

	ToDaemon chan []byte
	ToUser   chan []byte

	closed      chan struct{}
	closeOnce   sync.Once
	releaseSlot func()
}

func (r *Relay) Done() <-chan struct{} { return r.closed }

func (r *Relay) Close() {
	r.closeOnce.Do(func() { close(r.closed) })
}

type relayPending struct {
	ready       chan struct{}
	daemonID    string
	releaseSlot func()
}

// RequestRelay releases its slot exactly once. RegisterRelay hands the
// release to the Relay, failure paths run it directly.
func (p *Pool) RequestRelay(
	ctx context.Context,
	daemonID, relayID, userID string,
) (*Relay, error) {
	p.mu.Lock()
	if p.relayCounts[userID] >= maxRelaysPerPrincipal {
		p.mu.Unlock()
		return nil, ErrRelayLimit
	}
	p.relayCounts[userID]++
	p.mu.Unlock()

	release := sync.OnceFunc(func() {
		p.mu.Lock()
		p.releaseRelaySlotLocked(userID)
		p.mu.Unlock()
	})
	pend := &relayPending{ready: make(chan struct{}), daemonID: daemonID, releaseSlot: release}
	p.mu.Lock()
	p.pendingRelays[relayID] = pend
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		// A newer request for the same relayID may have replaced ours.
		if p.pendingRelays[relayID] == pend {
			delete(p.pendingRelays, relayID)
		}
		p.mu.Unlock()
	}()

	if err := p.sendToDaemonWait(daemonID, &nokkuv1.ConnectResponse{
		Msg: &nokkuv1.ConnectResponse_RelayOpen{
			RelayOpen: &nokkuv1.RelayOpen{RelayId: &relayID},
		},
	}, 5*time.Second); err != nil {
		release()
		return nil, fmt.Errorf("%w: %w", ErrRelayUnavailable, err)
	}

	var err error
	select {
	case <-pend.ready:
	case <-time.After(pendingSessionTimeout):
		err = fmt.Errorf("%w: relay request timed out", ErrRelayUnavailable)
	case <-ctx.Done():
		err = fmt.Errorf("%w: %w", ErrRelayUnavailable, ctx.Err())
	}

	// The relay may have registered just as the wait gave up, or be gone
	// again. Registration took the slot, so only release when it did not.
	p.mu.Lock()
	r := p.relays[relayID]
	p.mu.Unlock()
	if r == nil {
		release()
		if err == nil {
			err = fmt.Errorf("%w: relay closed before it was bridged", ErrRelayUnavailable)
		}
		return nil, err
	}
	return r, nil
}

// RegisterRelay returns nil unless this daemon was asked for this relay, so a
// rogue daemon cannot claim or fabricate one.
func (p *Pool) RegisterRelay(relayID, daemonID string) *Relay {
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
		relayID:     relayID,
		daemonID:    daemonID,
		ToDaemon:    make(chan []byte, relayBufferSize),
		ToUser:      make(chan []byte, relayBufferSize),
		closed:      make(chan struct{}),
		releaseSlot: pend.releaseSlot,
	}
	p.relays[relayID] = r
	p.ownLocked(daemonID).relays[relayID] = struct{}{}
	close(pend.ready)
	p.mu.Unlock()
	return r
}

func (p *Pool) UnregisterRelay(relayID string) {
	p.mu.Lock()
	r := p.relays[relayID]
	if r != nil {
		delete(p.relays, relayID)
		if o := p.owned[r.daemonID]; o != nil {
			delete(o.relays, relayID)
			p.disownLocked(r.daemonID)
		}
		r.Close()
	}
	p.mu.Unlock()
	if r != nil {
		r.releaseSlot()
	}
}

func (p *Pool) releaseRelaySlotLocked(userID string) {
	p.relayCounts[userID]--
	if p.relayCounts[userID] <= 0 {
		delete(p.relayCounts, userID)
	}
}
