package daemon

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/time/rate"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/db"
)

const (
	sendBufferSize = 64
	// behindReportGap keeps a daemon that flaps between behind and caught up from flooding the audit log.
	behindReportGap = 10 * time.Minute
	// reconnectWindow outlasts nokkud's longest reconnect backoff, a minute plus jitter.
	reconnectWindow = 2 * time.Minute
	// Access changes come in bursts, like a grant on many servers. The first is acted on at once, then the passes
	// over the workspace come this far apart.
	mergeWindow = 200 * time.Millisecond
	// The net under a lost notification, and what ends a grant that ran out on time.
	sweepEvery = time.Minute
)

type daemonConn struct {
	daemonID    string
	workspaceID string
	// state coalesces to one StateUpdate, apart so send never loses a message.
	send   chan *nokkuv1.ConnectResponse
	state  chan struct{}
	ctx    context.Context
	cancel context.CancelFunc

	mu sync.Mutex
	// wanted is the hash of what the daemon should hold, nil until the first pass over its workspace.
	wanted []byte
	// applied is what its last heartbeat said it holds.
	applied []byte
	heard   bool
	// wantedAtBeat is wanted as of the heartbeat before.
	wantedAtBeat []byte
	reportedAt   time.Time
	behindSince  atomic.Pointer[time.Time]
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
	// record is told when a daemon falls behind.
	record  func(context.Context, *audit.Event)
	started time.Time

	// dirty are the workspaces Reconcile has to look at, wake tells it there are some.
	dirtyMu sync.Mutex
	dirty   map[string]struct{}
	wake    chan struct{}

	// reportLimits paces each daemon's connection reports.
	reportMu     sync.Mutex
	reportLimits map[string]*rate.Limiter
}

// want sets what the daemon should hold and wakes it when its last heartbeat said something else.
func (c *daemonConn) want(hash []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wanted = hash
	if c.heard && !bytes.Equal(c.applied, hash) {
		c.poke()
	}
}

// heartbeat takes what the daemon holds and wakes it when that is not what it should. It fell behind when it
// still misses what was wanted one heartbeat ago, so a daemon busy with the latest change never counts.
func (c *daemonConn) heartbeat(applied []byte) (fell bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.applied, c.heard = applied, true
	if c.wanted == nil {
		return false
	}
	current := bytes.Equal(applied, c.wanted)
	if !current {
		c.poke()
	}
	behind := !current && c.wantedAtBeat != nil && !bytes.Equal(applied, c.wantedAtBeat)
	c.wantedAtBeat = c.wanted
	if !behind {
		c.behindSince.Store(nil)
		return false
	}
	if !c.behindSince.CompareAndSwap(nil, new(time.Now())) || time.Since(c.reportedAt) < behindReportGap {
		return false
	}
	c.reportedAt = time.Now()
	return true
}

// update is the message a poke sends, with what the daemon should hold by now.
func (c *daemonConn) update() *nokkuv1.ConnectResponse {
	c.mu.Lock()
	defer c.mu.Unlock()
	return &nokkuv1.ConnectResponse{
		Msg: &nokkuv1.ConnectResponse_StateUpdate{StateUpdate: &nokkuv1.StateUpdate{StateHash: c.wanted}},
	}
}

func New(conn connection, record func(context.Context, *audit.Event)) *Pool {
	return &Pool{
		byID:          make(map[string]*daemonConn),
		byWksp:        make(map[string]map[string]struct{}),
		relays:        make(map[string]*Relay),
		pendingRelays: make(map[string]*relayPending),
		conn:          conn,
		record:        record,
		started:       time.Now(),
		dirty:         make(map[string]struct{}),
		wake:          make(chan struct{}, 1),
		reportLimits:  make(map[string]*rate.Limiter),
	}
}

// Connected is what online means. The core runs as one instance.
func (p *Pool) Connected() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return slices.Collect(maps.Keys(p.byID))
}

// Settled says Connected is complete. After a start, daemons are still on their way back.
func (p *Pool) Settled() bool {
	return time.Since(p.started) > reconnectWindow
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

func (p *Pool) reportBehind(c *daemonConn, name string) {
	slog.Warn("daemon is behind", "daemon_id", c.daemonID)
	if p.record == nil {
		return
	}
	p.record(actor.WithWorkspace(c.ctx, actor.Workspace{ID: c.workspaceID}), &audit.Event{
		Action:  "DaemonBehind",
		Target:  c.daemonID,
		OK:      true,
		Details: map[string]any{"name": name},
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
		state:       make(chan struct{}, 1),
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
	// A daemon that was not held back has nothing to be remembered for.
	p.reportMu.Lock()
	if l := p.reportLimits[daemonID]; l != nil && l.Tokens() >= reportBurst {
		delete(p.reportLimits, daemonID)
	}
	p.reportMu.Unlock()
}

// Listen marks a workspace for Reconcile whenever its access changed.
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
	p.markAll()
	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			return err
		}
		p.mark(n.Payload)
	}
}

// mark has Reconcile look at a workspace. A workspace waits once, however often it is marked.
func (p *Pool) mark(workspaceID string) {
	p.dirtyMu.Lock()
	p.dirty[workspaceID] = struct{}{}
	p.dirtyMu.Unlock()
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// markAll marks every workspace with a daemon connected. No other has anyone to wake.
func (p *Pool) markAll() {
	p.mu.RLock()
	workspaces := slices.Collect(maps.Keys(p.byWksp))
	p.mu.RUnlock()
	for _, id := range workspaces {
		p.mark(id)
	}
}

// Reconcile runs until ctx ends. For each marked workspace it works out what every daemon should hold and wakes
// the ones that hold something else, so a change costs one pass and a sync per daemon it touches.
func (p *Pool) Reconcile(ctx context.Context) {
	sweep := time.NewTicker(sweepEvery)
	defer sweep.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-sweep.C:
			p.markAll()
			continue
		case <-p.wake:
		}
		p.dirtyMu.Lock()
		marked := p.dirty
		p.dirty = make(map[string]struct{})
		p.dirtyMu.Unlock()
		for workspaceID := range marked {
			if err := p.reconcile(ctx, workspaceID); err != nil && ctx.Err() == nil {
				// The sweep comes back to it.
				slog.Warn("working out what the daemons should hold", "workspace_id", workspaceID, "error", err)
			}
		}
		// A lone change, like a revoke, was acted on at once. What follows it within the window shares one pass.
		select {
		case <-ctx.Done():
			return
		case <-time.After(mergeWindow):
		}
	}
}

func (p *Pool) reconcile(ctx context.Context, workspaceID string) error {
	p.mu.RLock()
	daemons := make([]*daemonConn, 0, len(p.byWksp[workspaceID]))
	for daemonID := range p.byWksp[workspaceID] {
		if c := p.byID[daemonID]; c != nil {
			daemons = append(daemons, c)
		}
	}
	p.mu.RUnlock()
	if len(daemons) == 0 {
		return nil
	}
	hashes, err := Hashes(actor.WithWorkspace(ctx, actor.Workspace{ID: workspaceID}), p.conn)
	if err != nil {
		return err
	}
	// A daemon that is connected and gone from the database is told to stop by its next sync.
	gone, err := answer(nil, nil, nil, nil)
	if err != nil {
		return err
	}
	for _, c := range daemons {
		hash, ok := hashes[c.daemonID]
		if !ok {
			hash = gone.GetStateHash()
		}
		c.want(hash)
	}
	return nil
}

// poke never blocks, a pending update already covers this one.
func (c *daemonConn) poke() {
	select {
	case c.state <- struct{}{}:
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
