package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"
	"uuid"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
)

const sendBufferSize = 64

type Conn struct {
	daemonID    string
	workspaceID string
	// send carries control messages to the daemon. state carries version
	// updates. It is capacity-1 and replace-on-full, so a burst of changes
	// coalesces into one update per daemon. The two channels are separate so
	// coalescing can never drop a control message.
	send    chan *nokkuv1.ConnectResponse
	state   chan *nokkuv1.ConnectResponse
	stateMu sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
}

// Cancel tears down the connection context unless a reconnect already
// replaced this connection. Safe to call multiple times.
func (c *Conn) Cancel() {
	c.cancel()
}

type eventSubscriber struct {
	ch    chan *nokkuv1.SubscribeWorkspaceEventsResponse
	types []string
}

// connection is the subset of db.Connection the daemon package needs, so
// tests can stub it without a running Postgres.
type connection interface {
	WithTx(ctx context.Context, fn func(*db.Queries) error) error
	WithWorkspace(ctx context.Context, fn func(*db.Queries) error) error
}

type Pool struct {
	mu            sync.RWMutex
	byID          map[string]*Conn
	byWksp        map[string]map[string]struct{}
	sessions      map[string]*Session
	relays        map[string]*Relay
	pendingRelays map[string]*relayPending
	relayCounts   map[string]int
	events        map[string][]*eventSubscriber
	// versions holds the current state version per workspace. It is
	// in-memory only and resets on server restart. The Connect handler acks
	// any version mismatch on heartbeat, so a restarted server (counter 0)
	// makes every daemon re-sync once and no daemon can stay stale.
	versions map[string]int64
	conn     connection

	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc
}

func New(ctx context.Context, conn connection) *Pool {
	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
	p := &Pool{
		byID:           make(map[string]*Conn),
		byWksp:         make(map[string]map[string]struct{}),
		sessions:       make(map[string]*Session),
		relays:         make(map[string]*Relay),
		pendingRelays:  make(map[string]*relayPending),
		relayCounts:    make(map[string]int),
		events:         make(map[string][]*eventSubscriber),
		versions:       make(map[string]int64),
		conn:           conn,
		shutdownCtx:    shutdownCtx,
		shutdownCancel: shutdownCancel,
	}

	go func() {
		<-ctx.Done()
		p.Shutdown()
	}()

	return p
}

// Shutdown cancels all daemon connections and signals the shutdown context so
// long-lived handlers (SubscribeWorkspaceEvents, StreamCLILogin, etc.) return.
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
	var staleSessions []*Session
	var staleRelays []string
	for sessionID, session := range p.sessions {
		if session.daemonID == daemonID {
			delete(p.sessions, sessionID)
			staleSessions = append(staleSessions, session)
		}
	}
	for relayID, relay := range p.relays {
		if relay.daemonID == daemonID {
			staleRelays = append(staleRelays, relayID)
		}
	}
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

	if err := p.conn.WithTx(ctx, func(q *db.Queries) error {
		return q.UpdateDaemonOnlineStatus(ctx, &db.UpdateDaemonOnlineStatusParams{
			DaemonID: daemonID,
			Online:   true,
		})
	}); err != nil {
		slog.Error("failed to set daemon online", "daemon_id", daemonID, "error", err)
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
		}
	}
	// Tear down this daemon's sessions and relays even if the stream
	// handlers haven't noticed the control stream drop yet. shutdown() and
	// Close() are idempotent.
	var sessions []*Session
	var relayIDs []string
	for _, s := range p.sessions {
		if s.daemonID == daemonID {
			delete(p.sessions, s.sessionID)
			sessions = append(sessions, s)
		}
	}
	for id, r := range p.relays {
		if r.daemonID == daemonID {
			relayIDs = append(relayIDs, id)
		}
	}
	p.mu.Unlock()

	for _, s := range sessions {
		s.shutdown()
	}
	for _, id := range relayIDs {
		p.UnregisterRelay(id)
	}

	if err := p.conn.WithTx(
		context.Background(),
		func(q *db.Queries) error {
			return q.UpdateDaemonOnlineStatus(
				context.Background(),
				&db.UpdateDaemonOnlineStatusParams{
					DaemonID: daemonID,
					Online:   false,
				},
			)
		},
	); err != nil {
		slog.Error("failed to set daemon offline", "daemon_id", daemonID, "error", err)
	}

	c.cancel()
}

// Version returns the current state version of a workspace.
func (p *Pool) Version(workspaceID string) int64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.versions[workspaceID]
}

// HeartbeatVersion resolves a daemon heartbeat's version against the
// workspace counter. It reports the version to ack with and whether an ack
// is due at all. A mismatch means the daemon is behind, or the counter was
// reset by a server restart. Either way the daemon must re-sync so it
// cannot stay stale.
func (p *Pool) HeartbeatVersion(daemonID string, version int64) (int64, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	c, ok := p.byID[daemonID]
	if !ok {
		return 0, false
	}
	cur := p.versions[c.workspaceID]
	return cur, cur != version
}

// NotifyChange bumps the workspace state version and pushes a coalesced
// StateUpdate to every connected daemon. Each daemon re-syncs at most once
// per burst: its state channel holds one update and replaces it when a newer
// change lands before it is read.
func (p *Pool) NotifyChange(workspaceID string) {
	p.mu.Lock()
	p.versions[workspaceID]++
	version := p.versions[workspaceID]
	daemons := make([]*Conn, 0, len(p.byWksp[workspaceID]))
	for daemonID := range p.byWksp[workspaceID] {
		if c := p.byID[daemonID]; c != nil {
			daemons = append(daemons, c)
		}
	}
	p.mu.Unlock()

	msg := &nokkuv1.ConnectResponse{
		Msg: &nokkuv1.ConnectResponse_StateUpdate{
			StateUpdate: &nokkuv1.StateUpdate{StateVersion: &version},
		},
	}
	for _, c := range daemons {
		p.sendStateUpdate(c, msg)
	}
}

// sendStateUpdate delivers msg to c.state, replacing any older pending
// update. It never blocks the caller.
func (p *Pool) sendStateUpdate(c *Conn, msg *nokkuv1.ConnectResponse) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	select {
	case c.state <- msg:
	default:
		select {
		case <-c.state:
		default:
		}
		c.state <- msg
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

func (p *Pool) SubscribeEvents(
	workspaceID string,
	eventTypes []string,
) chan *nokkuv1.SubscribeWorkspaceEventsResponse {
	ch := make(chan *nokkuv1.SubscribeWorkspaceEventsResponse, 64)
	p.mu.Lock()
	p.events[workspaceID] = append(
		p.events[workspaceID],
		&eventSubscriber{ch: ch, types: eventTypes},
	)
	p.mu.Unlock()
	return ch
}

func (p *Pool) UnsubscribeEvents(
	workspaceID string,
	ch chan *nokkuv1.SubscribeWorkspaceEventsResponse,
) {
	p.mu.Lock()
	subs := p.events[workspaceID]
	for i, sub := range subs {
		if sub.ch == ch {
			p.events[workspaceID] = append(subs[:i], subs[i+1:]...)
			break
		}
	}
	// Drop the workspace key once the last subscriber leaves, so the map
	// doesn't accumulate an entry for every workspace that ever subscribed.
	if len(p.events[workspaceID]) == 0 {
		delete(p.events, workspaceID)
	}
	p.mu.Unlock()
}

func (p *Pool) PublishWorkspaceEvent(workspaceID, eventType, payloadJSON string) {
	event := &nokkuv1.SubscribeWorkspaceEventsResponse{
		Id:          new(uuid.NewV7().String()),
		Type:        &eventType,
		WorkspaceId: &workspaceID,
		PayloadJson: &payloadJSON,
		CreatedAt:   timestamppb.Now(),
	}
	p.mu.RLock()
	// Snapshot so UnsubscribeEvents' in-place append can't race the iteration.
	subs := slices.Clone(p.events[workspaceID])
	p.mu.RUnlock()
	for _, sub := range subs {
		if len(sub.types) == 0 {
			select {
			case sub.ch <- event:
			default:
			}
			continue
		}
		if slices.Contains(sub.types, eventType) {
			select {
			case sub.ch <- event:
			default:
			}
		}
	}
}
