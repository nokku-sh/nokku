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

const (
	sendBufferSize        = 64
	pendingSessionTimeout = 10 * time.Second
	replayBufferSize      = 64 * 1024
	// Caps how far the replay trim scans for a safe boundary.
	replayTrimScan = 256
)

type Conn struct {
	daemonID    string
	workspaceID string
	// send carries session requests to the daemon. state carries version
	// updates. It is capacity-1 and replace-on-full, so a burst of changes
	// coalesces into one update per daemon. The two channels are separate so
	// coalescing can never drop a session request.
	send    chan *nokkuv1.ConnectResponse
	state   chan *nokkuv1.ConnectResponse
	stateMu sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
}

// Session is the server-side handle for one live PTY session. It bridges
// the daemon's StreamSession bidi stream and any attached browser WebSocket.
type Session struct {
	sessionID string
	daemonID  string
	username  string
	userID    string

	send   chan *nokkuv1.DaemonSessionResponse
	Stdout chan []byte
	Exited chan struct{}

	replayMu  sync.Mutex
	replayBuf []byte

	shutdownOnce sync.Once
}

// DaemonID returns the daemon the session runs on.
func (s *Session) DaemonID() string { return s.daemonID }

// UserID returns the user who requested the session.
func (s *Session) UserID() string { return s.userID }

func (s *Session) shutdown() {
	s.shutdownOnce.Do(func() { close(s.Exited) })
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

// connection is the subset of db.Connection the pool needs, so tests can
// stub it without a running Postgres.
type connection interface {
	WithTx(ctx context.Context, fn func(*db.Queries) error) error
}

type Pool struct {
	mu       sync.RWMutex
	byID     map[string]*Conn
	byWksp   map[string]map[string]struct{}
	sessions map[string]*Session
	pending  map[string]chan struct{}
	events   map[string][]*eventSubscriber
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
		pending:        make(map[string]chan struct{}),
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
	for sessionID, session := range p.sessions {
		if session.daemonID == daemonID {
			delete(p.sessions, sessionID)
			staleSessions = append(staleSessions, session)
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
	// Tear down this daemon's sessions even if the StreamSession handler
	// hasn't noticed the control stream drop yet. shutdown() is idempotent.
	var sessions []*Session
	for _, s := range p.sessions {
		if s.daemonID == daemonID {
			delete(p.sessions, s.sessionID)
			sessions = append(sessions, s)
		}
	}
	p.mu.Unlock()

	for _, s := range sessions {
		s.shutdown()
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

func (p *Pool) RequestSession(
	ctx context.Context,
	daemonID, sessionID, username, userID string,
) error {
	pending := make(chan struct{})
	p.mu.Lock()
	p.pending[sessionID] = pending
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		// Only remove our own entry: a newer RequestSession for the same
		// sessionID may have replaced it while we were waiting.
		if p.pending[sessionID] == pending {
			delete(p.pending, sessionID)
		}
		p.mu.Unlock()
	}()

	if err := p.sendToDaemonWait(daemonID, &nokkuv1.ConnectResponse{
		Msg: &nokkuv1.ConnectResponse_Session{
			Session: &nokkuv1.DaemonSession{
				SessionId: &sessionID,
				Username:  &username,
				UserId:    &userID,
			},
		},
	}, 5*time.Second); err != nil {
		return err
	}

	select {
	case <-pending:
		return nil
	case <-time.After(pendingSessionTimeout):
		return fmt.Errorf("session request timed out")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *Pool) RegisterSession(sessionID, daemonID, username, userID string) *Session {
	s := &Session{
		sessionID: sessionID,
		daemonID:  daemonID,
		username:  username,
		userID:    userID,
		send:      make(chan *nokkuv1.DaemonSessionResponse, sendBufferSize),
		Stdout:    make(chan []byte, sendBufferSize),
		Exited:    make(chan struct{}),
	}
	p.mu.Lock()
	p.sessions[sessionID] = s
	if ch, ok := p.pending[sessionID]; ok {
		// Remove under the same lock so a concurrent duplicate RegisterSession
		// can't observe the entry and close an already-closed channel.
		delete(p.pending, sessionID)
		close(ch)
	}
	p.mu.Unlock()
	return s
}

// UnregisterSession removes a session from the pool map. The caller must call
// s.shutdown() (done by the StreamSession handler defer). It is idempotent.
func (p *Pool) UnregisterSession(sessionID string) {
	p.mu.Lock()
	delete(p.sessions, sessionID)
	p.mu.Unlock()
}

func (p *Pool) GetSession(sessionID string) *Session {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.sessions[sessionID]
}

func (p *Pool) ListSessions(daemonID string) []*nokkuv1.DaemonSession {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var result []*nokkuv1.DaemonSession
	for _, s := range p.sessions {
		if s.daemonID == daemonID {
			sessionID := s.sessionID
			username := s.username
			userID := s.userID
			result = append(result, &nokkuv1.DaemonSession{
				SessionId: &sessionID,
				Username:  &username,
				UserId:    &userID,
			})
		}
	}
	return result
}

func (p *Pool) CloseSession(sessionID string) {
	p.mu.Lock()
	s, ok := p.sessions[sessionID]
	if !ok {
		p.mu.Unlock()
		return
	}
	// Remove from map immediately so ListSessions stops returning it.
	delete(p.sessions, sessionID)
	p.mu.Unlock()
	s.shutdown()

	reason := "closed by user"
	select {
	case s.send <- &nokkuv1.DaemonSessionResponse{
		Msg: &nokkuv1.DaemonSessionResponse_Close{
			Close: &nokkuv1.DaemonCloseRequest{Reason: &reason},
		},
	}:
	default:
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

func (s *Session) SendStdin(data []byte) {
	select {
	case s.send <- &nokkuv1.DaemonSessionResponse{
		Msg: &nokkuv1.DaemonSessionResponse_Stdin{Stdin: data},
	}:
	default:
	}
}

func (s *Session) SendResize(width, height uint32) {
	select {
	case s.send <- &nokkuv1.DaemonSessionResponse{
		Msg: &nokkuv1.DaemonSessionResponse_Resize{
			Resize: &nokkuv1.DaemonResizeRequest{Width: &width, Height: &height},
		},
	}:
	default:
	}
}

// AppendStdout records a PTY output chunk in the replay buffer and forwards it
// to Stdout, atomic w.r.t. SnapshotForAttach so an attaching WebSocket never
// receives the same chunk twice.
func (s *Session) AppendStdout(data []byte) {
	s.replayMu.Lock()
	s.replayBuf = append(s.replayBuf, data...)
	if len(s.replayBuf) > replayBufferSize*2 {
		s.trimReplayLocked()
	}
	// Send while holding replayMu so SnapshotForAttach's drain sees a snapshot
	// and channel that are mutually consistent: a chunk already captured in the
	// replay copy is not also queued on Stdout (which would render it twice).
	select {
	case s.Stdout <- data:
	default:
	}
	s.replayMu.Unlock()
}

// SnapshotForAttach returns the replay buffer and a channel with only chunks
// that arrived after this snapshot. Older buffered-but-unsent chunks are
// consumed and discarded here. Callers send the replay first, then forward
// from the returned channel.
func (s *Session) SnapshotForAttach() (replay []byte, live <-chan []byte) {
	s.replayMu.Lock()
	replay = append([]byte(nil), s.replayBuf...)
	// Drain chunks already queued on Stdout: they are already in `replay`
	// (AppendStdout appends before sending), so a new attach would otherwise
	// render them twice. New chunks land in the channel and forward as live.
drain:
	for {
		select {
		case <-s.Stdout:
		default:
			break drain
		}
	}
	s.replayMu.Unlock()
	return replay, s.Stdout
}

func (s *Session) ReplayBuffer() []byte {
	s.replayMu.Lock()
	raw := append([]byte(nil), s.replayBuf...)
	s.replayMu.Unlock()
	if len(raw) == 0 {
		return nil
	}
	clean := SanitizeReplay(raw)
	if len(clean) <= replayBufferSize {
		return clean
	}
	// Take the last replayBufferSize bytes, then advance past leading bytes to
	// a safe boundary (escape start or printable char) so the replay never
	// begins mid-way through a cut escape sequence.
	clean = clean[len(clean)-replayBufferSize:]
	for i := 0; i < len(clean) && i < replayTrimScan; i++ {
		b := clean[i]
		if b == 0x1b {
			// Complete escape sequence: begin here.
			if i > 0 {
				clean = clean[i:]
			}
			break
		}
		if b >= 0x20 && b != 0x7f {
			// Printable character. Accept the cut line from here. Xterm
			// tolerates a partial leading line. Avoid trimming further so we
			// don't drop real output.
			if i > 0 {
				clean = clean[i:]
			}
			break
		}
		// Control/non-printable byte that isn't ESC. Likely a trailing byte
		// of a cut sequence, keep scanning.
	}
	return clean
}

// trimReplayLocked trims replayBuf to roughly replayBufferSize by dropping the
// oldest data up to a safe sequence boundary. Caller holds replayMu.
func (s *Session) trimReplayLocked() {
	excess := len(s.replayBuf) - replayBufferSize
	scan := min(excess+replayTrimScan, len(s.replayBuf))
	for i := excess; i < scan; i++ {
		b := s.replayBuf[i]
		if b == 0x1b || (b >= 0x20 && b != 0x7f) {
			s.replayBuf = append([]byte(nil), s.replayBuf[i:]...)
			return
		}
	}
	// No safe boundary found within the scan window. Hard cut at excess.
	s.replayBuf = append([]byte(nil), s.replayBuf[excess:]...)
}

func (s *Session) StdoutChan() <-chan []byte   { return s.Stdout }
func (s *Session) ExitedChan() <-chan struct{} { return s.Exited }
