package daemon

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
)

type stubConn struct{}

func (stubConn) WithTx(context.Context, func(*db.Queries) error) error {
	return nil
}

func (stubConn) WithWorkspace(context.Context, func(*db.Queries) error) error {
	return nil
}

func newTestPool(t *testing.T) *Pool {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return New(ctx, stubConn{})
}

// waitRelayPending blocks until the request goroutine's pending entry exists,
// so RegisterRelay in the test cannot win the race it isn't testing.
func waitRelayPending(t *testing.T, p *Pool, relayID string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		p.mu.RLock()
		_, ok := p.pendingRelays[relayID]
		p.mu.RUnlock()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("relay %s never became pending", relayID)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestPool_ReconnectStorm hammers RegisterDaemon/UnregisterDaemon with the
// same daemon IDs from many goroutines, as a reconnect storm would: each
// registration cancels its predecessor's connection.
func TestPool_ReconnectStorm(t *testing.T) {
	p := newTestPool(t)

	const (
		daemonIDs = 16
		wkspIDs   = 4
		rounds    = 100
	)
	var wg sync.WaitGroup
	for i := range daemonIDs {
		id := fmt.Sprintf("d%02d", i%daemonIDs)
		wksp := fmt.Sprintf("w%d", i%wkspIDs)
		for range rounds {
			wg.Go(func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				c := p.RegisterDaemon(ctx, id, wksp)
				p.UnregisterDaemon(id, c)
			})
		}
	}
	wg.Wait()

	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.byID) != 0 {
		t.Errorf("byID has %d entries after storm, want 0", len(p.byID))
	}
	for wksp, daemons := range p.byWksp {
		if len(daemons) != 0 {
			t.Errorf("workspace %s still lists %d daemons", wksp, len(daemons))
		}
	}
}

func TestPool_PokeStorm(t *testing.T) {
	p := newTestPool(t)

	const daemons = 32
	for i := range daemons {
		p.RegisterDaemon(context.Background(), fmt.Sprintf("d%02d", i), "w1")
	}

	var wg sync.WaitGroup
	for i := range daemons {
		id := fmt.Sprintf("d%02d", i)
		wg.Go(func() {
			for range 200 {
				p.Poke("w1")
			}
			p.mu.RLock()
			c := p.byID[id]
			p.mu.RUnlock()
			if c != nil {
				p.UnregisterDaemon(id, c)
			}
		})
	}
	wg.Wait()
}

// TestPool_PokeCoalesces verifies a burst of pokes collapses into one queued
// StateUpdate per daemon, and only reaches the poked workspace.
func TestPool_PokeCoalesces(t *testing.T) {
	p := newTestPool(t)
	c := p.RegisterDaemon(context.Background(), "d1", "w1")
	defer p.UnregisterDaemon("d1", c)
	other := p.RegisterDaemon(context.Background(), "d2", "w2")
	defer p.UnregisterDaemon("d2", other)

	for range 100 {
		p.Poke("w1")
	}

	if got := len(c.state); got != 1 {
		t.Fatalf("queued state updates = %d, want 1", got)
	}
	if msg := <-c.state; msg.GetStateUpdate() == nil {
		t.Fatal("queued message is not a StateUpdate")
	}
	if got := len(other.state); got != 0 {
		t.Fatalf("other workspace got %d state updates, want 0", got)
	}
}

// TestPool_PokeKeepsControlMessages verifies coalescing state updates never
// drops a control message queued on the same connection.
func TestPool_PokeKeepsControlMessages(t *testing.T) {
	p := newTestPool(t)
	c := p.RegisterDaemon(context.Background(), "d1", "w1")
	defer p.UnregisterDaemon("d1", c)

	rid := "r1"
	relayOpen := &nokkuv1.ConnectResponse{
		Msg: &nokkuv1.ConnectResponse_RelayOpen{
			RelayOpen: &nokkuv1.RelayOpen{RelayId: &rid},
		},
	}
	if err := p.sendToDaemonWait("d1", relayOpen, time.Second); err != nil {
		t.Fatalf("queue relay open: %v", err)
	}
	for range 10 {
		p.Poke("w1")
	}
	select {
	case msg := <-c.send:
		if msg.GetRelayOpen() == nil {
			t.Fatal("state storm replaced a control message")
		}
	default:
		t.Fatal("control message lost after state storm")
	}
}

// TestPool_SessionStdoutStorm hammers appendStdout against SnapshotForAttach
// (both take replayMu) and CloseSession, exercising the replay buffer and the
// shared Stdout channel under contention.
func TestPool_SessionStdoutStorm(t *testing.T) {
	p := newTestPool(t)
	s := p.registerSession("s1", "d1", "user", "u1")
	defer p.unregisterSession("s1")
	defer s.shutdown()

	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 2000 {
				s.appendStdout([]byte("chunk"))
			}
		})
		wg.Go(func() {
			for range 500 {
				_, live := s.SnapshotForAttach()
				select {
				case <-live:
				default:
				}
			}
		})
	}
	wg.Wait()
}

// TestPool_RelayRequestRace races RequestRelay (which may time out and
// clean up its pending entry and slot) against RegisterRelay (which closes
// the pending channel), the relay counterpart of the session request race.
func TestPool_RelayRequestRace(t *testing.T) {
	p := newTestPool(t)
	p.RegisterDaemon(context.Background(), "d1", "w1")

	const relays = 128
	var wg sync.WaitGroup
	for i := range relays {
		rid := fmt.Sprintf("r%d", i)
		wg.Add(2)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			if r, err := p.RequestRelay(ctx, "d1", rid, "u1"); err == nil {
				r.Close()
			}
		}()
		go func() {
			defer wg.Done()
			time.Sleep(time.Duration(i%3) * time.Millisecond)
			if r := p.RegisterRelay(rid, "d1"); r != nil {
				p.UnregisterRelay(rid)
			}
		}()
	}
	wg.Wait()

	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.pendingRelays) != 0 {
		t.Errorf("%d pending relay requests left behind", len(p.pendingRelays))
	}
	if len(p.relays) != 0 {
		t.Errorf("%d relays left behind", len(p.relays))
	}
	if len(p.relayCounts) != 0 {
		t.Errorf("relay slots left held: %v", p.relayCounts)
	}
}

// TestPool_RelayCap verifies the per-principal cap: the over-limit request is
// refused before anything reaches the daemon, other principals are unaffected,
// and released slots become available again.
func TestPool_RelayCap(t *testing.T) {
	p := newTestPool(t)
	p.RegisterDaemon(context.Background(), "d1", "w1")

	var wg sync.WaitGroup
	for i := range maxRelaysPerPrincipal {
		rid := fmt.Sprintf("r%d", i)
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := p.RequestRelay(ctx, "d1", rid, "u1"); err != nil {
				t.Errorf("RequestRelay %s: %v", rid, err)
			}
		})
		time.Sleep(time.Millisecond)
		if r := p.RegisterRelay(rid, "d1"); r == nil {
			t.Fatalf("relay %s was not pending", rid)
		}
	}
	wg.Wait()

	if _, err := p.RequestRelay(context.Background(), "d1", "over", "u1"); !errors.Is(err, ErrRelayLimit) {
		t.Fatalf("over-cap request: err=%v, want ErrRelayLimit", err)
	}

	// A different principal is unaffected: the request gets past the cap and
	// fails on the (never registered) pending wait instead.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := p.RequestRelay(ctx, "d1", "other", "u2"); errors.Is(err, ErrRelayLimit) {
		t.Fatal("u2 must not be blocked by u1's cap")
	}

	for i := range maxRelaysPerPrincipal {
		p.UnregisterRelay(fmt.Sprintf("r%d", i))
	}
	// Reusable, but the pending wait still needs a bound since nothing will
	// register this relay.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	if _, err := p.RequestRelay(ctx2, "d1", "again", "u1"); errors.Is(err, ErrRelayLimit) {
		t.Fatal("released slots must be reusable")
	}
}

// TestPool_RelayBridging walks a relay through the full request/register
// lifecycle and pushes bytes both directions through its channels.
func TestPool_RelayBridging(t *testing.T) {
	p := newTestPool(t)
	p.RegisterDaemon(context.Background(), "d1", "w1")

	type result struct {
		r   *Relay
		err error
	}
	res := make(chan result, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() {
		r, err := p.RequestRelay(ctx, "d1", "r1", "u1")
		res <- result{r, err}
	}()
	waitRelayPending(t, p, "r1")
	relay := p.RegisterRelay("r1", "d1")
	if relay == nil {
		t.Fatal("relay was not pending")
	}
	got := <-res
	if got.err != nil {
		t.Fatalf("RequestRelay: %v", got.err)
	}

	if r := p.RegisterRelay("ghost", "d1"); r != nil {
		t.Fatal("unknown relay id must not register")
	}

	relay.ToDaemon <- []byte("ping")
	relay.ToUser <- []byte("pong")
	if data := <-relay.ToDaemon; string(data) != "ping" {
		t.Errorf("ToDaemon carried %q", data)
	}
	if data := <-relay.ToUser; string(data) != "pong" {
		t.Errorf("ToUser carried %q", data)
	}

	select {
	case <-relay.Done():
		t.Fatal("relay closed before unregister")
	default:
	}

	p.UnregisterRelay("r1")
	select {
	case <-relay.Done():
	default:
		t.Fatal("relay not closed by UnregisterRelay")
	}
	p.UnregisterRelay("r1")

	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.relayCounts) != 0 {
		t.Errorf("relay slots left held: %v", p.relayCounts)
	}
}

// TestPool_UnregisterDaemonClosesRelays verifies a daemon disconnect tears
// down its relays and frees their slots.
func TestPool_UnregisterDaemonClosesRelays(t *testing.T) {
	p := newTestPool(t)
	c := p.RegisterDaemon(context.Background(), "d1", "w1")

	res := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() {
		_, err := p.RequestRelay(ctx, "d1", "r1", "u1")
		res <- err
	}()
	waitRelayPending(t, p, "r1")
	if r := p.RegisterRelay("r1", "d1"); r == nil {
		t.Fatal("relay was not pending")
	}
	if err := <-res; err != nil {
		t.Fatalf("RequestRelay: %v", err)
	}

	p.UnregisterDaemon("d1", c)
	p.mu.RLock()
	relay := p.relays["r1"]
	p.mu.RUnlock()
	if relay != nil {
		t.Fatal("relay outlived its daemon")
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.relayCounts) != 0 {
		t.Errorf("relay slots left held: %v", p.relayCounts)
	}
}

// TestPool_Shutdown verifies Shutdown is idempotent and closes Done.
func TestPool_Shutdown(t *testing.T) {
	p := newTestPool(t)
	p.RegisterDaemon(context.Background(), "d1", "w1")

	p.Shutdown()
	p.Shutdown()

	select {
	case <-p.Done():
	case <-time.After(time.Second):
		t.Fatal("Done() not closed after Shutdown")
	}
}

// A disconnect tears down exactly that daemon's sessions and relays, and
// leaves no index entry behind.
func TestPool_DisconnectDropsOnlyOwnSessions(t *testing.T) {
	p := newTestPool(t)
	c1 := p.RegisterDaemon(context.Background(), "d1", "w1")
	c2 := p.RegisterDaemon(context.Background(), "d2", "w1")
	defer p.UnregisterDaemon("d2", c2)
	mine := p.registerSession("s1", "d1", "root", "u1")
	other := p.registerSession("s2", "d2", "root", "u1")

	p.UnregisterDaemon("d1", c1)

	select {
	case <-mine.exited:
	default:
		t.Fatal("session of the disconnected daemon is still running")
	}
	select {
	case <-other.exited:
		t.Fatal("session of another daemon was torn down")
	default:
	}
	if p.GetSession("s1") != nil || p.GetSession("s2") == nil {
		t.Fatal("session map out of sync with the teardown")
	}
	if _, ok := p.owned["d1"]; ok {
		t.Fatal("index entry of the disconnected daemon survived")
	}
	if got := len(p.ListSessions("d2")); got != 1 {
		t.Fatalf("ListSessions(d2) = %d, want 1", got)
	}

	p.unregisterSession("s2")
	if _, ok := p.owned["d2"]; ok {
		t.Fatal("empty index entry was not dropped")
	}
}

// A beat stamps only newly connected daemons, a full beat every connected one.
func TestPool_HeartbeatBatch(t *testing.T) {
	p := newTestPool(t)
	for range 3 {
		c := p.RegisterDaemon(t.Context(), "d1", "w1")
		p.UnregisterDaemon("d1", c)
	}
	c := p.RegisterDaemon(t.Context(), "d2", "w1")
	defer p.UnregisterDaemon("d2", c)

	if got := p.heartbeatBatch(false); !slices.Equal(got, []string{"d2"}) {
		t.Fatalf("beat = %v, want [d2]", got)
	}
	if got := p.heartbeatBatch(false); len(got) != 0 {
		t.Fatalf("second beat = %v, want nothing new", got)
	}
	if got := p.heartbeatBatch(true); !slices.Equal(got, []string{"d2"}) {
		t.Fatalf("full beat = %v, want [d2]", got)
	}
}
