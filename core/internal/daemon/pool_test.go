package daemon

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/db"
)

type stubConn struct{}

// versionConn answers the state version query with what the test stored.
type versionConn struct {
	stubConn

	version atomic.Int64
}

type versionRow int64

func (stubConn) SysTx(context.Context, func(*db.Queries) error) error {
	return nil
}

func (stubConn) TenantTx(context.Context, func(*db.Queries) error) error {
	return nil
}

func (c *versionConn) SysTx(_ context.Context, fn func(*db.Queries) error) error {
	return fn(db.New(c))
}

func (c *versionConn) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errors.New("not in this test")
}

func (c *versionConn) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("not in this test")
}

func (c *versionConn) QueryRow(context.Context, string, ...any) pgx.Row {
	return versionRow(c.version.Load())
}

func (r versionRow) Scan(dest ...any) error {
	*dest[0].(*int64) = int64(r)
	return nil
}

func newTestPool(t *testing.T) *Pool {
	t.Helper()
	return New(stubConn{})
}

// waitRelayPending stops registerRelay winning a race the test isn't about.
func waitRelayPending(t *testing.T, p *Pool, relayID string) {
	t.Helper()
	require.Eventually(t, func() bool {
		p.mu.RLock()
		defer p.mu.RUnlock()
		_, ok := p.pendingRelays[relayID]
		return ok
	}, time.Second, time.Millisecond, "relay %s never became pending", relayID)
}

// A reconnect storm: each registration cancels its predecessor's connection.
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
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				c := p.registerDaemon(ctx, id, wksp)
				p.unregisterDaemon(id, c)
			})
		}
	}
	wg.Wait()

	p.mu.RLock()
	defer p.mu.RUnlock()
	assert.Empty(t, p.byID, "byID after the storm")
	for wksp, daemons := range p.byWksp {
		assert.Empty(t, daemons, "workspace %s still lists daemons", wksp)
	}
}

func TestPool_ConnectedIn(t *testing.T) {
	p := newTestPool(t)
	p.registerDaemon(t.Context(), "d1", "w1")
	p.registerDaemon(t.Context(), "d2", "w2")
	p.registerDaemon(t.Context(), "d3", "w1")

	assert.ElementsMatch(t, []string{"d1", "d3"}, p.ConnectedIn("w1"))
	assert.Empty(t, p.ConnectedIn("w3"), "a workspace without daemons lists some")
	assert.ElementsMatch(t, []string{"d1", "d2", "d3"}, p.Connected())
}

func TestPool_PokeStorm(t *testing.T) {
	p := newTestPool(t)

	const daemons = 32
	for i := range daemons {
		p.registerDaemon(t.Context(), fmt.Sprintf("d%02d", i), "w1")
	}

	var wg sync.WaitGroup
	for i := range daemons {
		id := fmt.Sprintf("d%02d", i)
		wg.Go(func() {
			for range 200 {
				p.poke("w1")
			}
			p.mu.RLock()
			c := p.byID[id]
			p.mu.RUnlock()
			if c != nil {
				p.unregisterDaemon(id, c)
			}
		})
	}
	wg.Wait()
}

// A burst of pokes is one queued StateUpdate, only in the poked workspace.
func TestPool_PokeCoalesces(t *testing.T) {
	p := newTestPool(t)
	c := p.registerDaemon(t.Context(), "d1", "w1")
	defer p.unregisterDaemon("d1", c)
	other := p.registerDaemon(t.Context(), "d2", "w2")
	defer p.unregisterDaemon("d2", other)

	for range 100 {
		p.poke("w1")
	}

	require.Len(t, c.state, 1, "queued state updates")
	require.NotNil(t, (<-c.state).GetStateUpdate(), "queued message is not a StateUpdate")
	require.Empty(t, other.state, "the other workspace got state updates")
}

// Coalescing state updates never drops a queued control message.
func TestPool_PokeKeepsControlMessages(t *testing.T) {
	p := newTestPool(t)
	c := p.registerDaemon(t.Context(), "d1", "w1")
	defer p.unregisterDaemon("d1", c)

	rid := "r1"
	relayOpen := &nokkuv1.ConnectResponse{
		Msg: &nokkuv1.ConnectResponse_RelayOpen{
			RelayOpen: &nokkuv1.RelayOpen{RelayId: &rid},
		},
	}
	require.NoError(t, p.sendToDaemonWait(t.Context(), "d1", relayOpen, time.Second), "queue relay open")
	for range 10 {
		p.poke("w1")
	}
	select {
	case msg := <-c.send:
		require.NotNil(t, msg.GetRelayOpen(), "state storm replaced a control message")
	default:
		t.Fatal("control message lost after state storm")
	}
}

// RequestRelay may time out while registerRelay closes the pending channel.
func TestPool_RelayRequestRace(t *testing.T) {
	p := newTestPool(t)
	p.registerDaemon(t.Context(), "d1", "w1")

	const relays = 128
	var wg sync.WaitGroup
	for i := range relays {
		rid := fmt.Sprintf("r%d", i)
		wg.Add(2)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
			defer cancel()
			if r, err := p.RequestRelay(ctx, "d1", rid, "u1", ""); err == nil {
				r.close()
			}
		}()
		go func() {
			defer wg.Done()
			time.Sleep(time.Duration(i%3) * time.Millisecond)
			if r := p.registerRelay(rid, "d1"); r != nil {
				p.UnregisterRelay(rid)
			}
		}()
	}
	wg.Wait()

	p.mu.RLock()
	defer p.mu.RUnlock()
	assert.Empty(t, p.pendingRelays, "pending relay requests left behind")
	assert.Empty(t, p.relays, "relays left behind")
	assert.Empty(t, p.relayCounts, "relay slots left held")
}

// An over-limit request never reaches the daemon, and released slots come back.
func TestPool_RelayCap(t *testing.T) {
	p := newTestPool(t)
	p.registerDaemon(t.Context(), "d1", "w1")

	var wg sync.WaitGroup
	for i := range maxRelaysPerPrincipal {
		rid := fmt.Sprintf("r%d", i)
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			_, err := p.RequestRelay(ctx, "d1", rid, "u1", "")
			assert.NoError(t, err, "RequestRelay %s", rid)
		})
		waitRelayPending(t, p, rid)
		require.NotNil(t, p.registerRelay(rid, "d1"), "relay %s was not pending", rid)
	}
	wg.Wait()

	_, err := p.RequestRelay(t.Context(), "d1", "over", "u1", "")
	require.ErrorIs(t, err, ErrRelayLimit, "over-cap request")

	// Another principal passes the cap and ends in the pending wait instead.
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	_, err = p.RequestRelay(ctx, "d1", "other", "u2", "")
	require.NotErrorIs(t, err, ErrRelayLimit, "u2 must not be blocked by u1's cap")

	for i := range maxRelaysPerPrincipal {
		p.UnregisterRelay(fmt.Sprintf("r%d", i))
	}
	// Reusable. Nothing registers it, so the pending wait needs a bound.
	ctx2, cancel2 := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel2()
	_, err = p.RequestRelay(ctx2, "d1", "again", "u1", "")
	require.NotErrorIs(t, err, ErrRelayLimit, "released slots must be reusable")
}

// A request to a stuck daemon ends with its own ctx and leaves nothing held.
func TestPool_RelayRequestEndsWithItsContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newTestPool(t)
		c := p.registerDaemon(t.Context(), "d1", "w1")
		for range cap(c.send) {
			c.send <- &nokkuv1.ConnectResponse{}
		}

		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, err := p.RequestRelay(ctx, "d1", "r1", "u1", "")
		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Equal(t, 50*time.Millisecond, time.Since(start), "the request outlived its context")

		p.mu.RLock()
		defer p.mu.RUnlock()
		assert.Empty(t, p.pendingRelays, "the pending request was left behind")
		assert.Empty(t, p.relayCounts, "the relay slot is still held")
	})
}

// A relay through request and register, with bytes in both directions.
func TestPool_RelayBridging(t *testing.T) {
	p := newTestPool(t)
	p.registerDaemon(t.Context(), "d1", "w1")

	type result struct {
		r   *Relay
		err error
	}
	res := make(chan result, 1)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	go func() {
		r, err := p.RequestRelay(ctx, "d1", "r1", "u1", "")
		res <- result{r, err}
	}()
	waitRelayPending(t, p, "r1")
	relay := p.registerRelay("r1", "d1")
	require.NotNil(t, relay, "relay was not pending")
	got := <-res
	require.NoError(t, got.err, "RequestRelay")

	require.Nil(t, p.registerRelay("ghost", "d1"), "unknown relay id must not register")

	relay.toDaemon <- []byte("ping")
	relay.toUser <- []byte("pong")
	assert.Equal(t, "ping", string(<-relay.toDaemon), "ToDaemon")
	assert.Equal(t, "pong", string(<-relay.toUser), "ToUser")

	select {
	case <-relay.done():
		t.Fatal("relay closed before unregister")
	default:
	}

	p.UnregisterRelay("r1")
	select {
	case <-relay.done():
	default:
		t.Fatal("relay not closed by UnregisterRelay")
	}
	p.UnregisterRelay("r1")

	p.mu.RLock()
	defer p.mu.RUnlock()
	assert.Empty(t, p.relayCounts, "relay slots left held")
}

// A daemon disconnect tears down its relays and frees their slots.
func TestPool_UnregisterDaemonClosesRelays(t *testing.T) {
	p := newTestPool(t)
	c := p.registerDaemon(t.Context(), "d1", "w1")

	res := make(chan error, 1)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	go func() {
		_, err := p.RequestRelay(ctx, "d1", "r1", "u1", "")
		res <- err
	}()
	waitRelayPending(t, p, "r1")
	require.NotNil(t, p.registerRelay("r1", "d1"), "relay was not pending")
	require.NoError(t, <-res, "RequestRelay")

	p.unregisterDaemon("d1", c)
	p.mu.RLock()
	defer p.mu.RUnlock()
	require.Nil(t, p.relays["r1"], "relay outlived its daemon")
	assert.Empty(t, p.relayCounts, "relay slots left held")
}

// A disconnect tears down only that daemon's sessions, its index entry too.
func TestPool_DisconnectDropsOnlyOwnSessions(t *testing.T) {
	p := newTestPool(t)
	c1 := p.registerDaemon(t.Context(), "d1", "w1")
	c2 := p.registerDaemon(t.Context(), "d2", "w1")
	defer p.unregisterDaemon("d2", c2)
	// Bare sessions, the teardown only needs the index and close.
	closed := map[string]bool{}
	for id, daemonID := range map[string]string{"s1": "d1", "s2": "d2"} {
		s := &Session{sessionID: id, daemonID: daemonID, close: func() { closed[id] = true }}
		p.mu.Lock()
		p.sessions[id] = s
		p.ownLocked(daemonID).sessions[id] = s
		p.mu.Unlock()
	}

	p.unregisterDaemon("d1", c1)

	require.True(t, closed["s1"], "session of the disconnected daemon is still running")
	require.False(t, closed["s2"], "session of another daemon was torn down")
	require.Nil(t, p.sessions["s1"], "session map out of sync with the teardown")
	require.NotNil(t, p.sessions["s2"], "session map out of sync with the teardown")
	require.NotContains(t, p.owned, "d1", "index entry of the disconnected daemon survived")
	require.Len(t, p.ListSessions("d2"), 1)
}

// A notification can get lost, so the heartbeat reads the version on its own.
func TestPool_StateVersionNeedsNoListener(t *testing.T) {
	conn := &versionConn{}
	conn.version.Store(1)
	p := New(conn)

	v, err := p.stateVersion(t.Context(), "w1")
	require.NoError(t, err)
	assert.Equal(t, int64(1), v)

	conn.version.Store(2)
	v, err = p.stateVersion(t.Context(), "w1")
	require.NoError(t, err)
	assert.Equal(t, int64(2), v, "the change never reached the heartbeat check")
}

// A daemon is behind only on a version it had a whole heartbeat to reach.
func TestHeartbeatFindsADaemonThatFellBehind(t *testing.T) {
	c := &daemonConn{}
	assert.False(t, c.heartbeat(0, 5), "the first heartbeat has nothing to compare with")
	assert.False(t, c.heartbeat(5, 7), "a daemon that reached the version of the last heartbeat")
	assert.Nil(t, c.behindSince.Load())

	assert.True(t, c.heartbeat(6, 7), "a daemon still short of the version of the last heartbeat")
	since := c.behindSince.Load()
	require.NotNil(t, since)
	assert.False(t, c.heartbeat(6, 7), "falling behind is reported once")
	assert.Equal(t, since, c.behindSince.Load(), "the first moment stays")

	assert.False(t, c.heartbeat(7, 9), "a daemon that caught up")
	assert.Nil(t, c.behindSince.Load())
}
