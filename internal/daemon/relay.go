package daemon

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
)

const (
	maxRelaysPerPrincipal = 8
	relayBufferSize       = 16
	// How long the daemon has to answer a RelayOpen before the request
	// gives up.
	pendingSessionTimeout = 10 * time.Second
)

var (
	ErrRelayLimit       = errors.New("relay limit reached")
	ErrRelayUnavailable = errors.New("relay unavailable")
	ErrCAInactive       = errors.New("certificate authority is not active")
)

// Relay is the server-side handle for one relayed SSH connection. It bridges
// the daemon's DaemonRelay bidi stream and the user's Relay bidi stream.
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
	ready    chan struct{}
	daemonID string
	// releaseSlot returns the per-principal slot exactly once, whether the
	// request fails, the relay registers, or the relay is torn down.
	releaseSlot func()
}

// RequestRelay pushes a RelayOpen to the daemon and waits for its
// DaemonRelay stream to arrive. The per-principal slot acquired here is
// owned by a release-once closure: RegisterRelay hands it to the Relay,
// every failure path runs it directly.
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
		// Only remove our own entry: a newer request for the same relayID
		// may have replaced it while we were waiting.
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

	// The daemon may have registered the relay just as the wait gave up, or
	// it may already be gone again (daemon disconnect racing the wakeup).
	// Registration consumed the slot, so only release when it did not.
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

// RegisterRelay records the daemon's relay stream for relayID and releases
// the waiting requester. It returns nil when no relay was requested under
// this id, or when the registering daemon does not match the one the
// request was sent to, so a rogue daemon cannot claim or fabricate a relay.
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
	close(pend.ready)
	p.mu.Unlock()
	return r
}

// UnregisterRelay tears a relay down and releases its per-principal slot.
// Safe to call more than once.
func (p *Pool) UnregisterRelay(relayID string) {
	p.mu.Lock()
	r := p.relays[relayID]
	if r != nil {
		delete(p.relays, relayID)
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
