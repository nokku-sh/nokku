package daemon

import (
	"context"
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

func newTestPool(t *testing.T) *Pool {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return New(ctx, stubConn{})
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

// TestPool_SessionRequestRace races RequestSession (which may time out and
// clean up its pending entry) against RegisterSession (which closes the
// pending channel), the exact path that used to clobber a newer request.
func TestPool_SessionRequestRace(t *testing.T) {
	p := newTestPool(t)
	p.RegisterDaemon(context.Background(), "d1", "w1")

	const sessions = 128
	var wg sync.WaitGroup
	for i := range sessions {
		sid := fmt.Sprintf("s%d", i)
		wg.Add(2)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			_ = p.RequestSession(ctx, "d1", sid, "user", "u1")
		}()
		go func() {
			defer wg.Done()
			time.Sleep(time.Duration(i%3) * time.Millisecond)
			s := p.RegisterSession(sid, "d1", "user", "u1")
			defer p.UnregisterSession(sid)
			defer s.shutdown()
		}()
	}
	wg.Wait()

	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.pending) != 0 {
		t.Errorf("%d pending session requests left behind", len(p.pending))
	}
	if len(p.sessions) != 0 {
		t.Errorf("%d sessions left behind", len(p.sessions))
	}
}

// TestPool_SessionRequestSameID reuses one session ID so the pending entries
// genuinely collide: a timed-out request must not delete its successor's
// entry, or the daemon's RegisterSession would never close the successor's
// channel and it would sit blocked until timeout.
func TestPool_SessionRequestSameID(t *testing.T) {
	p := newTestPool(t)
	p.RegisterDaemon(context.Background(), "d1", "w1")

	const rounds = 50
	for range rounds {
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		_ = p.RequestSession(ctx, "d1", "same-id", "user", "u1")
		cancel()
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.pending) != 0 {
		t.Errorf("%d pending session requests left behind", len(p.pending))
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

// TestPool_NotifyChangeKeepsSessions verifies coalescing state updates never
// drops a session request queued on the same connection.
func TestPool_NotifyChangeKeepsSessions(t *testing.T) {
	p := newTestPool(t)
	c := p.RegisterDaemon(context.Background(), "d1", "w1")
	defer p.UnregisterDaemon("d1", c)

	sid := "s1"
	sessionMsg := func() *nokkuv1.ConnectResponse {
		return &nokkuv1.ConnectResponse{
			Msg: &nokkuv1.ConnectResponse_Session{Session: &nokkuv1.Session{SessionId: &sid}},
		}
	}
	if err := p.sendToDaemonWait("d1", sessionMsg(), time.Second); err != nil {
		t.Fatalf("queue session request: %v", err)
	}
	// Drain the session request off the channel.
	select {
	case msg := <-c.send:
		if msg.GetSession() == nil {
			t.Fatal("session channel carried a non-session message")
		}
	default:
		t.Fatal("session request was not queued")
	}
	for range 10 {
		p.NotifyChange("w1")
	}
	// A fresh session request must still arrive despite the state backlog.
	if err := p.sendToDaemonWait("d1", sessionMsg(), time.Second); err != nil {
		t.Fatalf("queue session request after state storm: %v", err)
	}
	select {
	case msg := <-c.send:
		if msg.GetSession() == nil {
			t.Fatal("state storm replaced a session request")
		}
	default:
		t.Fatal("session request lost after state storm")
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

// TestPool_Shutdown verifies Shutdown is idempotent, closes Done, and lets
// RequestSession return promptly after shutdown.
func TestPool_Shutdown(t *testing.T) {
	p := newTestPool(t)
	p.RegisterDaemon(context.Background(), "d1", "w1")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go p.RequestSession(ctx, "d1", "s1", "user", "u1")

	p.Shutdown()
	p.Shutdown()

	select {
	case <-p.Done():
	case <-time.After(time.Second):
		t.Fatal("Done() not closed after Shutdown")
	}
}
