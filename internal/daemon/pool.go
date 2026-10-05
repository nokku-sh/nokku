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

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/db"
)

const (
	sendBufferSize = 64
	// Each tick stamps newly connected daemons, so a reconnect storm costs
	// one UPDATE per tick. Every heartbeatFullEvery ticks stamps all of them.
	heartbeatTick      = 2 * time.Second
	heartbeatFullEvery = 5
)

var stateUpdate = &nokkuv1.ConnectResponse{
	Msg: &nokkuv1.ConnectResponse_StateUpdate{StateUpdate: &nokkuv1.StateUpdate{}},
}

type daemonConn struct {
	daemonID    string
	workspaceID string
	// state holds at most one pending StateUpdate so bursts coalesce. It is
	// separate from send so coalescing never drops a control message.
	send   chan *nokkuv1.ConnectResponse
	state  chan *nokkuv1.ConnectResponse
	ctx    context.Context
	cancel context.CancelFunc
}

// connection lets tests stub db.Connection without Postgres.
type connection interface {
	WithTx(ctx context.Context, fn func(*db.Queries) error) error
	WithWorkspace(ctx context.Context, fn func(*db.Queries) error) error
}

// owned lets a disconnect tear down a daemon's sessions without scanning the pool.
type owned struct {
	sessions map[string]*Session
	relays   map[string]struct{}
}

type Pool struct {
	mu            sync.RWMutex
	byID          map[string]*daemonConn
	byWksp        map[string]map[string]struct{}
	owned         map[string]*owned
	sessions      map[string]*Session
	relays        map[string]*Relay
	pendingRelays map[string]*relayPending
	relayCounts   map[string]int
	// versions is refreshed by the listener on every change notification.
	versions map[string]int64
	// fresh holds daemons connected since the last heartbeat.
	fresh map[string]struct{}
	conn  connection

	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc
}

func New(ctx context.Context, conn connection) *Pool {
	shutdownCtx, shutdownCancel := context.WithCancel(ctx)
	p := &Pool{
		byID:           make(map[string]*daemonConn),
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

	context.AfterFunc(ctx, p.shutdown)
	go p.heartbeat(ctx)

	return p
}

// heartbeat never marks a daemon offline, it just stops being seen. That also
// covers a crashed instance.
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

// dropOwnedLocked returns what to tear down outside the lock.
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

func (p *Pool) ownLocked(daemonID string) *owned {
	o := p.owned[daemonID]
	if o == nil {
		o = &owned{sessions: make(map[string]*Session), relays: make(map[string]struct{})}
		p.owned[daemonID] = o
	}
	return o
}

func (p *Pool) disownLocked(daemonID string) {
	if o := p.owned[daemonID]; o != nil && len(o.sessions) == 0 && len(o.relays) == 0 {
		delete(p.owned, daemonID)
	}
}

// shutdown is idempotent.
func (p *Pool) shutdown() {
	p.shutdownCancel()
	p.mu.Lock()
	for _, c := range p.byID {
		c.cancel()
	}
	p.mu.Unlock()
}

func (p *Pool) registerDaemon(ctx context.Context, daemonID, workspaceID string) *daemonConn {
	ctx, cancel := context.WithCancel(ctx)
	c := &daemonConn{
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
		session.close()
	}
	for _, relayID := range staleRelays {
		p.UnregisterRelay(relayID)
	}
	return c
}

func (p *Pool) unregisterDaemon(daemonID string, c *daemonConn) {
	p.mu.Lock()
	cur, ok := p.byID[daemonID]
	if !ok {
		p.mu.Unlock()
		return
	}
	// A reconnect replaced this connection.
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
	// The stream handlers may not have noticed the drop yet.
	sessions, relayIDs := p.dropOwnedLocked(daemonID)
	p.mu.Unlock()

	for _, s := range sessions {
		s.close()
	}
	for _, id := range relayIDs {
		p.UnregisterRelay(id)
	}
	c.cancel()
}

func (p *Pool) poke(workspaceID string) {
	p.mu.RLock()
	daemons := make([]*daemonConn, 0, len(p.byWksp[workspaceID]))
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

// Listen pokes a workspace's daemons on every trigger notification.
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
		p.poke(ws)
	}
}

// stateVersion fills the cache on a miss only if the listener did not store a
// fresher value meanwhile.
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

// poke never blocks, a pending update already covers this one.
func (c *daemonConn) poke() {
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
