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

// stubConn satisfies the pool's connection interface without a database; it
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

// TestPool_BroadcastStorm broadcasts to a full workspace while daemons drop
// off, forcing sendToDaemon to race UnregisterDaemon's map teardown.
func TestPool_BroadcastStorm(t *testing.T) {
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
				p.Broadcast("w1", &nokkuv1.Notification{DaemonId: &id})
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
