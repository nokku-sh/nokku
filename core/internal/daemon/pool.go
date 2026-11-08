package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/db"
)

const sendBufferSize = 64

var stateUpdate = &nokkuv1.ConnectResponse{
	Msg: &nokkuv1.ConnectResponse_StateUpdate{StateUpdate: &nokkuv1.StateUpdate{}},
}

type daemonConn struct {
	daemonID    string
	workspaceID string
	// state coalesces to one StateUpdate, apart so send never loses a message.
	send   chan *nokkuv1.ConnectResponse
	state  chan *nokkuv1.ConnectResponse
	ctx    context.Context
	cancel context.CancelFunc
	// wanted is the core's version at the last heartbeat.
	wanted      int64
	behindSince atomic.Pointer[time.Time]
}

// connection lets tests stub db.Connection without Postgres.
type connection interface {
	SysTx(ctx context.Context, fn func(*db.Queries) error) error
	TenantTx(ctx context.Context, fn func(*db.Queries) error) error
}

// Pool holds the connected daemons and their relays, a relay ends only with its own stream.
type Pool struct {
	mu            sync.RWMutex
	byID          map[string]*daemonConn
	byWksp        map[string]map[string]struct{}
	relays        map[string]*Relay
	pendingRelays map[string]*relayPending
	conn          connection
	// Record is told when a daemon falls behind. Set before the server starts.
	Record func(context.Context, *audit.Event)
}

// heartbeat checks against the core's version one heartbeat ago, so a daemon
// busy with the latest change never counts.
func (c *daemonConn) heartbeat(applied, current int64) (fell bool) {
	behind := applied < c.wanted
	c.wanted = current
	if !behind {
		c.behindSince.Store(nil)
		return false
	}
	return c.behindSince.CompareAndSwap(nil, new(time.Now()))
}

func New(conn connection) *Pool {
	return &Pool{
		byID:          make(map[string]*daemonConn),
		byWksp:        make(map[string]map[string]struct{}),
		relays:        make(map[string]*Relay),
		pendingRelays: make(map[string]*relayPending),
		conn:          conn,
	}
}

// Connected is what online means. The core runs as one instance.
func (p *Pool) Connected() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return slices.Collect(maps.Keys(p.byID))
}

func (p *Pool) ConnectedIn(workspaceID string) []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return slices.Collect(maps.Keys(p.byWksp[workspaceID]))
}

func (p *Pool) IsConnected(daemonID string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.byID[daemonID]
	return ok
}

// BehindSince is when a daemon stopped keeping up, zero while it does. It may
// be enforcing revoked access, and a failed sync only shows in that host's log.
func (p *Pool) BehindSince(daemonID string) time.Time {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if c := p.byID[daemonID]; c != nil {
		if since := c.behindSince.Load(); since != nil {
			return *since
		}
	}
	return time.Time{}
}

func (p *Pool) BehindIn(workspaceID string) int32 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var n int32
	for daemonID := range p.byWksp[workspaceID] {
		if c := p.byID[daemonID]; c != nil && c.behindSince.Load() != nil {
			n++
		}
	}
	return n
}

func (p *Pool) reportBehind(c *daemonConn, name string, applied, current int64) {
	slog.Warn("daemon is behind", "daemon_id", c.daemonID, "applied", applied, "current", current)
	if p.Record == nil {
		return
	}
	p.Record(actor.WithWorkspace(c.ctx, actor.Workspace{ID: c.workspaceID}), &audit.Event{
		Action:  "DaemonBehind",
		Target:  c.daemonID,
		OK:      true,
		Details: map[string]any{"name": name, "applied": applied, "current": current},
	})
}

func (p *Pool) markSeen(ctx context.Context, daemonID string) {
	if err := p.conn.TenantTx(ctx, func(q *db.Queries) error {
		return q.MarkDaemonSeen(ctx, daemonID)
	}); err != nil {
		slog.Warn("mark daemon seen", "daemon_id", daemonID, "error", err)
	}
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
		}
	}
	p.mu.Unlock()
	c.cancel()
}

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
	p.pokeAll()
	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			return err
		}
		p.poke(n.Payload)
	}
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

// Read every time, so a lost notification only waits for the next heartbeat.
func (p *Pool) stateVersion(ctx context.Context, workspaceID string) (int64, error) {
	var v int64
	if err := p.conn.SysTx(ctx, func(q *db.Queries) (err error) {
		v, err = q.GetWorkspaceStateVersion(ctx, workspaceID)
		return err
	}); err != nil {
		return 0, err
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

// A caller that is gone must not wait behind a daemon that reads nothing. A
// reconnect can close the connection under the send, the new one gets a try.
func (p *Pool) sendToDaemonWait(
	ctx context.Context,
	daemonID string,
	msg *nokkuv1.ConnectResponse,
	timeout time.Duration,
) error {
	t := time.NewTimer(timeout)
	defer t.Stop()
	for range 2 {
		p.mu.RLock()
		c, ok := p.byID[daemonID]
		p.mu.RUnlock()
		if !ok {
			return fmt.Errorf("daemon %s not connected", daemonID)
		}
		select {
		case c.send <- msg:
			// A closed connection's buffer can still have room, nobody reads it.
			if c.ctx.Err() == nil {
				return nil
			}
		case <-t.C:
			return fmt.Errorf("daemon %s send timeout", daemonID)
		case <-c.ctx.Done():
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return fmt.Errorf("daemon %s disconnected", daemonID)
}
