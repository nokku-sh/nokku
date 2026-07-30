package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	sendBufferSize        = 64
	pendingSessionTimeout = 10 * time.Second
	replayBufferSize      = 64 * 1024
	// replayTrimScan caps how far we scan when trimming the replay to a safe
	// sequence boundary, keeping the cost bounded.
	replayTrimScan = 256
)

type Conn struct {
	daemonID    string
	workspaceID string
	send        chan *nokkuv1.ConnectResponse
	ctx         context.Context
	cancel      context.CancelFunc
}

// Session is the server-side handle for one live PTY session. It bridges
// the daemon's StreamSession bidi stream and any attached browser WebSocket.
type Session struct {
	sessionID string
	daemonID  string
	username  string
	userID    string

	send   chan *nokkuv1.SessionResponse
	Stdout chan []byte
	Exited chan struct{}

	replayMu  sync.Mutex
	replayBuf []byte

	shutdownOnce sync.Once
}

func (s *Session) shutdown() {
	s.shutdownOnce.Do(func() { close(s.Exited) })
}

type eventSubscriber struct {
	ch    chan *nokkuv1.SubscribeWorkspaceEventsResponse
	types []string
}

type Pool struct {
	mu       sync.RWMutex
	byID     map[string]*Conn
	byWksp   map[string]map[string]struct{}
	sessions map[string]*Session
	pending  map[string]chan struct{}
	events   map[string][]*eventSubscriber
	conn     *db.Connection

	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc
}

func New(ctx context.Context, conn *db.Connection) *Pool {
	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
	p := &Pool{
		byID:           make(map[string]*Conn),
		byWksp:         make(map[string]map[string]struct{}),
		sessions:       make(map[string]*Session),
		pending:        make(map[string]chan struct{}),
		events:         make(map[string][]*eventSubscriber),
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
// that long-lived handlers (SubscribeWorkspaceEvents, StreamCLILogin, etc.)
// return promptly. Idempotent and safe to call from any goroutine.
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
		ctx:         ctx,
		cancel:      cancel,
	}
	p.mu.Lock()
	p.byID[daemonID] = c
	if _, ok := p.byWksp[workspaceID]; !ok {
		p.byWksp[workspaceID] = make(map[string]struct{})
	}
	p.byWksp[workspaceID][daemonID] = struct{}{}
	p.mu.Unlock()

	if err := p.conn.Q.UpdateDaemonOnlineStatus(ctx, &db.UpdateDaemonOnlineStatusParams{
		DaemonID: daemonID,
		Online:   true,
	}); err != nil {
		slog.Error("failed to set daemon online", "daemon_id", daemonID, "error", err)
	}
	return c
}

func (p *Pool) UnregisterDaemon(daemonID string) {
	p.mu.Lock()
	c, ok := p.byID[daemonID]
	if !ok {
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
	// Tear down every live session of this daemon immediately, even if the
	// session's StreamSession handler hasn't noticed the control stream drop
	// yet. shutdown() is idempotent: the handler's own defer will no-op.
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

	if err := p.conn.Q.UpdateDaemonOnlineStatus(
		context.Background(),
		&db.UpdateDaemonOnlineStatusParams{
			DaemonID: daemonID,
			Online:   false,
		},
	); err != nil {
		slog.Error("failed to set daemon offline", "daemon_id", daemonID, "error", err)
	}

	c.cancel()
}

func (p *Pool) Broadcast(workspaceID string, n *nokkuv1.Notification) {
	p.mu.RLock()
	daemons := p.byWksp[workspaceID]
	p.mu.RUnlock()
	for daemonID := range daemons {
		p.sendToDaemon(daemonID, &nokkuv1.ConnectResponse{
			Msg: &nokkuv1.ConnectResponse_Notification{Notification: n},
		})
	}
}

func (p *Pool) sendToDaemon(daemonID string, msg *nokkuv1.ConnectResponse) {
	p.mu.RLock()
	c, ok := p.byID[daemonID]
	p.mu.RUnlock()
	if !ok {
		return
	}
	select {
	case c.send <- msg:
	default:
		slog.Warn("daemon send buffer full, dropping message", "daemon_id", daemonID)
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
		delete(p.pending, sessionID)
		p.mu.Unlock()
	}()

	if err := p.sendToDaemonWait(daemonID, &nokkuv1.ConnectResponse{
		Msg: &nokkuv1.ConnectResponse_Session{
			Session: &nokkuv1.Session{
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
		send:      make(chan *nokkuv1.SessionResponse, sendBufferSize),
		Stdout:    make(chan []byte, sendBufferSize),
		Exited:    make(chan struct{}),
	}
	p.mu.Lock()
	p.sessions[sessionID] = s
	if ch, ok := p.pending[sessionID]; ok {
		close(ch)
	}
	p.mu.Unlock()
	return s
}

// UnregisterSession removes a session from the pool map. The caller is
// responsible for invoking s.shutdown() to close Exited; this is done by the
// StreamSession handler defer and is idempotent.
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

func (p *Pool) ListSessions(daemonID string) []*nokkuv1.Session {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var result []*nokkuv1.Session
	for _, s := range p.sessions {
		if s.daemonID == daemonID {
			sessionID := s.sessionID
			username := s.username
			userID := s.userID
			result = append(result, &nokkuv1.Session{
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

	reason := "closed by user"
	select {
	case s.send <- &nokkuv1.SessionResponse{
		Msg: &nokkuv1.SessionResponse_Close{
			Close: &nokkuv1.CloseRequest{Reason: &reason},
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
	p.mu.Unlock()
}

func (p *Pool) PublishWorkspaceEvent(workspaceID, eventType, payloadJSON string) {
	event := &nokkuv1.SubscribeWorkspaceEventsResponse{
		Id:          new(uuid.New().String()),
		Type:        &eventType,
		WorkspaceId: &workspaceID,
		PayloadJson: &payloadJSON,
		CreatedAt:   timestamppb.Now(),
	}
	p.mu.RLock()
	subs := p.events[workspaceID]
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
	case s.send <- &nokkuv1.SessionResponse{
		Msg: &nokkuv1.SessionResponse_Stdin{Stdin: data},
	}:
	default:
	}
}

func (s *Session) SendResize(width, height uint32) {
	select {
	case s.send <- &nokkuv1.SessionResponse{
		Msg: &nokkuv1.SessionResponse_Resize{
			Resize: &nokkuv1.ResizeRequest{Width: &width, Height: &height},
		},
	}:
	default:
	}
}

// AppendStdout records a PTY output chunk in the replay buffer and forwards it
// to the live Stdout channel. The two operations are atomic w.r.t.
// SnapshotForAttach so that an attaching WebSocket never receives the same
// chunk twice (once in the replay and once on the channel).
func (s *Session) AppendStdout(data []byte) {
	s.replayMu.Lock()
	s.replayBuf = append(s.replayBuf, data...)
	if len(s.replayBuf) > replayBufferSize*2 {
		s.trimReplayLocked()
	}
	s.replayMu.Unlock()

	select {
	case s.Stdout <- data:
	default:
	}
}

// SnapshotForAttach returns the replay buffer to send to a freshly attached
// WebSocket, and a drain channel that will receive only chunks that arrived
// after this snapshot (older buffered-but-unsent chunks are consumed and
// discarded here). Callers must send the replay first, then forward from the
// returned channel.
func (s *Session) SnapshotForAttach() (replay []byte, live <-chan []byte) {
	s.replayMu.Lock()
	replay = append([]byte(nil), s.replayBuf...)
	// Drain any chunks already queued on Stdout: they are already in `replay`
	// (AppendStdout appends before sending), so a new attach would otherwise
	// render them a second time. New chunks appended after this point land in
	// the channel and are forwarded as live output.
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
	// Take the last replayBufferSize bytes, then advance past any leading
	// bytes until we hit a safe boundary (an escape start or a printable
	// char) so we never begin mid-way through a cut escape sequence.
	clean = clean[len(clean)-replayBufferSize:]
	for i := 0; i < len(clean) && i < replayTrimScan; i++ {
		b := clean[i]
		if b == 0x1b {
			// Start of a complete escape sequence — begin here.
			if i > 0 {
				clean = clean[i:]
			}
			break
		}
		if b >= 0x20 && b != 0x7f {
			// Printable character — accept the cut line from here; xterm
			// tolerates a partial leading line. Avoid trimming further so we
			// don't drop real output.
			if i > 0 {
				clean = clean[i:]
			}
			break
		}
		// Control/non-printable byte that isn't ESC: likely a trailing byte
		// of a cut sequence — keep scanning.
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
	// No safe boundary found within the scan window; hard cut at excess.
	s.replayBuf = append([]byte(nil), s.replayBuf[excess:]...)
}

func (s *Session) StdoutChan() <-chan []byte   { return s.Stdout }
func (s *Session) ExitedChan() <-chan struct{} { return s.Exited }
