package daemon

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
)

// stubConn satisfies the pool's connection interface without a database. It
// skips the online-status updates so no SQL ever runs.
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

// TestPool_EventSubscriberStorm subscribes and unsubscribes many event
// subscribers while events are published, with subscriber goroutines draining
// like the real handler (select on ctx.Done / channel).
func TestPool_EventSubscriberStorm(t *testing.T) {
	p := newTestPool(t)

	const (
		subs   = 32
		events = 500
	)
	var wg sync.WaitGroup
	for i := range subs {
		var types []string
		if i%2 == 0 {
			types = []string{"daemon.accepted"}
		}
		ch := p.SubscribeEvents("w1", types)
		stop := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				case <-ch:
				}
			}
		}()
		go func() {
			defer wg.Done()
			for range events {
				p.PublishWorkspaceEvent("w1", "daemon.accepted", "{}")
				p.PublishWorkspaceEvent("w1", "daemon.removed", "{}")
			}
			close(stop)
			p.UnsubscribeEvents("w1", ch)
		}()
	}
	wg.Wait()

	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.events) != 0 {
		t.Errorf("%d event subscribers left behind", len(p.events))
	}
}

// TestPool_NotifyChangeStorm pushes state updates to a full workspace while
// daemons drop off, forcing sendStateUpdate to race UnregisterDaemon's map
// teardown and the state channel's replace-on-full path.
func TestPool_NotifyChangeStorm(t *testing.T) {
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
				p.NotifyChange("w1")
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

	// Every change bumped the workspace version. The final version must
	// reflect the whole storm (not lost updates on the counter).
	if got := p.Version("w1"); got < daemons*200 {
		t.Errorf("Version(w1) = %d, want >= %d", got, daemons*200)
	}
}

// TestPool_NotifyChangeCoalesces verifies a burst of changes collapses into
// at most one queued StateUpdate per daemon, carrying the newest version.
func TestPool_NotifyChangeCoalesces(t *testing.T) {
	p := newTestPool(t)
	c := p.RegisterDaemon(context.Background(), "d1", "w1")
	defer p.UnregisterDaemon("d1", c)

	// Drain the first update. The rest must coalesce into a single queued
	// message that no longer blocks NotifyChange.
	select {
	case <-c.state:
	default:
	}
	for range 100 {
		p.NotifyChange("w1")
	}

	var last int64
	drained := 0
	for {
		select {
		case msg := <-c.state:
			drained++
			last = msg.GetStateUpdate().GetStateVersion()
		default:
			if drained > 1 {
				t.Errorf("coalescing left %d queued updates, want <= 1", drained)
			}
			if drained == 0 {
				t.Fatal("no state update was delivered")
			}
			if last != p.Version("w1") {
				t.Errorf("delivered version %d, want newest %d", last, p.Version("w1"))
			}
			return
		}
	}
}

// TestPool_NotifyChangeKeepsControlMessages verifies coalescing state
// updates never drops a control message queued on the same connection.
func TestPool_NotifyChangeKeepsControlMessages(t *testing.T) {
	p := newTestPool(t)
	c := p.RegisterDaemon(context.Background(), "d1", "w1")
	defer p.UnregisterDaemon("d1", c)

	relayMsg := func(rid string) *nokkuv1.ConnectResponse {
		return &nokkuv1.ConnectResponse{
			Msg: &nokkuv1.ConnectResponse_RelayOpen{
				RelayOpen: &nokkuv1.RelayOpen{RelayId: &rid},
			},
		}
	}
	if err := p.sendToDaemonWait("d1", relayMsg("r1"), time.Second); err != nil {
		t.Fatalf("queue relay open: %v", err)
	}
	// Drain the control message off the channel.
	select {
	case msg := <-c.send:
		if msg.GetRelayOpen() == nil {
			t.Fatal("control channel carried a non-relay message")
		}
	default:
		t.Fatal("relay open was not queued")
	}
	for range 10 {
		p.NotifyChange("w1")
	}
	// A fresh control message must still arrive despite the state backlog.
	if err := p.sendToDaemonWait("d1", relayMsg("r2"), time.Second); err != nil {
		t.Fatalf("queue relay open after state storm: %v", err)
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

// TestPool_HeartbeatVersion verifies the ack decision. Quiet when up to
// date, ack when behind. After a server restart resets the counter, every
// daemon that synced before must re-sync once.
func TestPool_HeartbeatVersion(t *testing.T) {
	p := newTestPool(t)
	p.RegisterDaemon(context.Background(), "d1", "w1")
	defer p.UnregisterDaemon("d1", p.byID["d1"])

	// Fresh workspace, fresh daemon: nothing to do.
	if _, ack := p.HeartbeatVersion("d1", 0); ack {
		t.Fatal("fresh daemon in a fresh workspace must not be acked")
	}

	// A change bumps the workspace: the daemon is behind and gets an ack
	// with the current version.
	p.NotifyChange("w1")
	version, ack := p.HeartbeatVersion("d1", 0)
	if !ack || version != 1 {
		t.Fatalf("behind daemon: ack=%v version=%d, want ack=true version=1", ack, version)
	}

	// After the daemon synced (local version == counter), it stays quiet.
	if _, ack := p.HeartbeatVersion("d1", 1); ack {
		t.Fatal("up-to-date daemon must not be acked")
	}

	// Server restart: the counter starts over, so a daemon that synced
	// before must re-sync even though it reports a higher version.
	p.mu.Lock()
	p.versions = make(map[string]int64)
	p.mu.Unlock()
	version, ack = p.HeartbeatVersion("d1", 1)
	if !ack || version != 0 {
		t.Fatalf("after restart: ack=%v version=%d, want ack=true version=0", ack, version)
	}

	// Once it re-synced to the reset counter, heartbeats are quiet again.
	if _, ack := p.HeartbeatVersion("d1", 0); ack {
		t.Fatal("re-synced daemon must not be acked")
	}

	// Unknown daemons never get acks.
	if _, ack := p.HeartbeatVersion("ghost", 0); ack {
		t.Fatal("unknown daemon must not be acked")
	}
}

// TestPool_SessionStdoutStorm hammers AppendStdout against SnapshotForAttach
// (both take replayMu) and CloseSession, exercising the replay buffer and the
// shared Stdout channel under contention.
func TestPool_SessionStdoutStorm(t *testing.T) {
	p := newTestPool(t)
	s := p.RegisterSession("s1", "d1", "user", "u1")
	defer p.UnregisterSession("s1")
	defer s.shutdown()

	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 2000 {
				s.AppendStdout([]byte("chunk"))
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
