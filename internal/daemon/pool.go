package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
)

const (
	sendBufferSize = 64
	// Every heartbeatTick the pool stamps newly connected daemons, so they
	// show online quickly and a reconnect storm costs one UPDATE per tick.
	// Every heartbeatFullEvery ticks it stamps all of them, well inside
	// db.DaemonOnlineWindow.
	heartbeatTick      = 2 * time.Second
	heartbeatFullEvery = 5
)

var stateUpdate = &nokkuv1.ConnectResponse{
	Msg: &nokkuv1.ConnectResponse_StateUpdate{StateUpdate: &nokkuv1.StateUpdate{}},
}

type Conn struct {
	daemonID    string
	workspaceID string
	// send carries control messages to the daemon. state holds at most one
	// pending StateUpdate, so a burst of changes coalesces into one sync. The
	// two channels are separate so coalescing can never drop a control
	// message.
	send   chan *nokkuv1.ConnectResponse
	state  chan *nokkuv1.ConnectResponse
	ctx    context.Context
	cancel context.CancelFunc
}

// Cancel tears down the connection context unless a reconnect already
// replaced this connection. Safe to call multiple times.
func (c *Conn) Cancel() {
	c.cancel()
}

// connection is the subset of db.Connection the daemon package needs, so
// tests can stub it without a running Postgres.
type connection interface {
	WithTx(ctx context.Context, fn func(*db.Queries) error) error
	WithWorkspace(ctx context.Context, fn func(*db.Queries) error) error
}

// owned indexes one daemon's sessions and relays, so a disconnect tears
// them down without scanning the whole pool.
type owned struct {
	sessions map[string]*Session
	relays   map[string]struct{}
}

type Pool struct {
	mu            sync.RWMutex
	byID          map[string]*Conn
	byWksp        map[string]map[string]struct{}
	owned         map[string]*owned
	sessions      map[string]*Session
	relays        map[string]*Relay
	pendingRelays map[string]*relayPending
	relayCounts   map[string]int
	// versions caches the workspace state version for heartbeat checks. The
	// listener refreshes an entry on every change notification.
	versions map[string]int64
	// fresh holds daemons connected since the last heartbeat.
	fresh map[string]struct{}
	conn  connection

	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc
}

func New(ctx context.Context, conn connection) *Pool {
	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
	p := &Pool{
		byID:           make(map[string]*Conn),
		byWksp:         make(map[string]map[string]struct{}),
		owned:          make(map[string]*owned),
		sessions:       make(map[string]*Session),
		relays:         make(map[string]*Relay),
		pendingRelays:  make(map[string]*relayPending),
		relayCounts:    make(map[string]int),
		versions:       make(map[string]int64),
		fresh:          make(map[string]struct{}),
		conn:           conn,
		shutdownCtx:    shutdownCtx,
		shutdownCancel: shutdownCancel,
	}

	go func() {
		<-ctx.Done()
		p.Shutdown()
	}()
	go p.heartbeat(ctx)

	return p
}

// heartbeat stamps last_seen_at for the daemons connected to this instance.
// Nothing marks a daemon offline: it simply stops being seen, which also
// covers an instance that crashed.
func (p *Pool) heartbeat(ctx context.Context) {
	ticker := time.NewTicker(heartbeatTick)
	defer ticker.Stop()
	for tick := 0; ; tick++ {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		ids := p.heartbeatBatch(tick%heartbeatFullEvery == 0)
		if len(ids) == 0 {
			continue
		}
		if err := p.conn.WithTx(ctx, func(q *db.Queries) error {
			return q.TouchDaemons(ctx, ids)
		}); err != nil {
			slog.Warn("daemon heartbeat", "error", err, "daemons", len(ids))
		}
	}
}

// heartbeatBatch returns the daemons to stamp: all connected ones on a full
// beat, otherwise only those connected since the last beat.
func (p *Pool) heartbeatBatch(full bool) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var ids []string
	if full {
		ids = slices.Collect(maps.Keys(p.byID))
	} else {
		ids = slices.Collect(maps.Keys(p.fresh))
	}
	clear(p.fresh)
	return ids
}

// dropOwnedLocked detaches every session and relay of a daemon from the pool
// and returns them for teardown outside the lock. Caller holds p.mu.
func (p *Pool) dropOwnedLocked(daemonID string) ([]*Session, []string) {
	o := p.owned[daemonID]
	if o == nil {
		return nil, nil
	}
	sessions := slices.Collect(maps.Values(o.sessions))
	relays := slices.Collect(maps.Keys(o.relays))
	for _, s := range sessions {
		delete(p.sessions, s.sessionID)
	}
	delete(p.owned, daemonID)
	return sessions, relays
}

// ownLocked returns the daemon's index entry, creating it. Caller holds p.mu.
func (p *Pool) ownLocked(daemonID string) *owned {
	o := p.owned[daemonID]
	if o == nil {
		o = &owned{sessions: make(map[string]*Session), relays: make(map[string]struct{})}
		p.owned[daemonID] = o
	}
	return o
}

// disownLocked drops an emptied index entry. Caller holds p.mu.
func (p *Pool) disownLocked(daemonID string) {
	if o := p.owned[daemonID]; o != nil && len(o.sessions) == 0 && len(o.relays) == 0 {
		delete(p.owned, daemonID)
	}
}

// Shutdown cancels all daemon connections and signals the shutdown context so
// long-lived handlers such as web sessions return.
// Idempotent, safe from any goroutine.
func (p *Pool) Shutdown() {
	p.shutdownCancel()
	p.mu.Lock()
	for _, c := range p.byID {
		c.cancel()
	}
	p.mu.Unlock()
}

// Done returns a channel that is closed when the pool is shutting down.
func (p *Pool) Done() <-chan struct{} {
	return p.shutdownCtx.Done()
}

func (p *Pool) RegisterDaemon(ctx context.Context, daemonID, workspaceID string) *Conn {
	ctx, cancel := context.WithCancel(ctx)
	c := &Conn{
		daemonID:    daemonID,
		workspaceID: workspaceID,
		send:        make(chan *nokkuv1.ConnectResponse, sendBufferSize),
		state:       make(chan *nokkuv1.ConnectResponse, 1),
		ctx:         ctx,
		cancel:      cancel,
	}
	p.mu.Lock()
	previous := p.byID[daemonID]
	staleSessions, staleRelays := p.dropOwnedLocked(daemonID)
	p.fresh[daemonID] = struct{}{}
	if previous != nil && previous.workspaceID != workspaceID {
		if daemons := p.byWksp[previous.workspaceID]; daemons != nil {
			delete(daemons, daemonID)
			if len(daemons) == 0 {
				delete(p.byWksp, previous.workspaceID)
			}
		}
	}
	p.byID[daemonID] = c
	if _, ok := p.byWksp[workspaceID]; !ok {
		p.byWksp[workspaceID] = make(map[string]struct{})
	}
	p.byWksp[workspaceID][daemonID] = struct{}{}
	p.mu.Unlock()
	if previous != nil {
		previous.cancel()
	}
	for _, session := range staleSessions {
		session.shutdown()
	}
	for _, relayID := range staleRelays {
		p.UnregisterRelay(relayID)
	}
	return c
}

func (p *Pool) UnregisterDaemon(daemonID string, c *Conn) {
	p.mu.Lock()
	cur, ok := p.byID[daemonID]
	if !ok {
		p.mu.Unlock()
		return
	}
	// If the map entry no longer points at the connection this handler owns, a
	// reconnect replaced it.
	if cur != c {
		p.mu.Unlock()
		return
	}
	wksp := c.workspaceID
	delete(p.byID, daemonID)
	if daemons, ok := p.byWksp[wksp]; ok {
		delete(daemons, daemonID)
		if len(daemons) == 0 {
			delete(p.byWksp, wksp)
			delete(p.versions, wksp)
		}
	}
	delete(p.fresh, daemonID)
	// Tear down this daemon's sessions and relays even if the stream
	// handlers haven't noticed the control stream drop yet. shutdown() and
	// Close() are idempotent.
	sessions, relayIDs := p.dropOwnedLocked(daemonID)
	p.mu.Unlock()

	for _, s := range sessions {
		s.shutdown()
	}
	for _, id := range relayIDs {
		p.UnregisterRelay(id)
	}
	c.cancel()
}

// Poke tells every connected daemon of a workspace to re-sync.
func (p *Pool) Poke(workspaceID string) {
	p.mu.RLock()
	daemons := make([]*Conn, 0, len(p.byWksp[workspaceID]))
	for daemonID := range p.byWksp[workspaceID] {
		if c := p.byID[daemonID]; c != nil {
			daemons = append(daemons, c)
		}
	}
	p.mu.RUnlock()
	for _, c := range daemons {
		c.poke()
	}
}

// Listen pokes a workspace's daemons whenever the database reports a state
// change for it. The notifications come from triggers and arrive on commit.
// It reconnects until ctx is done.
func (p *Pool) Listen(ctx context.Context, cfg *pgx.ConnConfig) {
	for ctx.Err() == nil {
		if err := p.listen(ctx, cfg); err != nil && ctx.Err() == nil {
			slog.Warn("state listener disconnected", "error", err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
		}
	}
}

func (p *Pool) listen(ctx context.Context, cfg *pgx.ConnConfig) error {
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	if _, err := conn.Exec(ctx, "LISTEN nokku_state"); err != nil {
		return err
	}
	// Anything that changed while we were not listening went unnoticed.
	p.mu.Lock()
	clear(p.versions)
	p.mu.Unlock()
	p.pokeAll()
	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			return err
		}
		// Read after commit, so the cached version is never older than the
		// change that fired the notification.
		ws := n.Payload
		var version int64
		if err := p.conn.WithTx(ctx, func(q *db.Queries) (err error) {
			version, err = q.GetWorkspaceStateVersion(ctx, ws)
			return err
		}); err != nil {
			slog.Warn("read workspace state version", "workspace_id", ws, "error", err)
			p.mu.Lock()
			delete(p.versions, ws)
			p.mu.Unlock()
		} else {
			p.mu.Lock()
			if _, ok := p.byWksp[ws]; ok {
				p.versions[ws] = version
			}
			p.mu.Unlock()
		}
		p.Poke(ws)
	}
}

// stateVersion returns a workspace's state version, from the cache when the
// listener has seen it. A miss reads the database and fills the cache only if
// the listener did not store a fresher value meanwhile.
func (p *Pool) stateVersion(ctx context.Context, workspaceID string) (int64, error) {
	p.mu.RLock()
	v, ok := p.versions[workspaceID]
	p.mu.RUnlock()
	if ok {
		return v, nil
	}
	if err := p.conn.WithTx(ctx, func(q *db.Queries) (err error) {
		v, err = q.GetWorkspaceStateVersion(ctx, workspaceID)
		return err
	}); err != nil {
		return 0, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if cached, ok := p.versions[workspaceID]; ok {
		return cached, nil
	}
	if _, ok := p.byWksp[workspaceID]; ok {
		p.versions[workspaceID] = v
	}
	return v, nil
}

func (p *Pool) pokeAll() {
	p.mu.RLock()
	daemons := slices.Collect(maps.Values(p.byID))
	p.mu.RUnlock()
	for _, c := range daemons {
		c.poke()
	}
}

// poke queues a StateUpdate. A pending one already covers it, so a burst of
// changes costs the daemon one sync. It never blocks the caller.
func (c *Conn) poke() {
	select {
	case c.state <- stateUpdate:
	default:
	}
}

func (p *Pool) sendToDaemonWait(
	daemonID string,
	msg *nokkuv1.ConnectResponse,
	timeout time.Duration,
) error {
	p.mu.RLock()
	c, ok := p.byID[daemonID]
	p.mu.RUnlock()
	if !ok {
		return fmt.Errorf("daemon %s not connected", daemonID)
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case c.send <- msg:
		return nil
	case <-t.C:
		return fmt.Errorf("daemon %s send timeout", daemonID)
	case <-c.ctx.Done():
		return fmt.Errorf("daemon %s disconnected", daemonID)
	}
}
