package daemon

import (
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
	"uuid"

	"golang.org/x/crypto/ssh"
	"golang.org/x/time/rate"

	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	nokkussh "github.com/nokku-sh/nokku/internal/ssh"
	"github.com/nokku-sh/nokku/internal/sshclient"
)

const (
	replayBufferSize = 64 * 1024
	// Caps how far the replay trim scans for a safe boundary.
	replayTrimScan = 256

	sessionTTL      = 8 * time.Hour
	sessionIdle     = 30 * time.Minute
	sessionDialTime = 30 * time.Second
	sessionCertTTL  = time.Hour
	idleCheckEvery  = 30 * time.Second

	// Binds shell output toward the browser, inherited from the old PTY
	// path. sshclient chunks at 32 KB, below the burst, so WaitN is valid.
	webStdoutRate  = 512 << 10
	webStdoutBurst = 64 << 10
)

// SessionConfig carries what StartSession needs to dial the daemon's
// sshd: the ephemeral session certificate is minted from CA on start.
type SessionConfig struct {
	DaemonID  string
	SessionID string
	Username  string
	UserID    string
	CA        *db.CertificateAuthority
	// HostPrincipal is the host certificate principal to require, the
	// daemon's target id.
	HostPrincipal string
}

// Session is the server-side handle for one live SSH session. It bridges
// the session's SSH channel over its relay and any attached browser
// WebSocket. Its public shape is what the websocket handler depends on:
// SendStdin, SendResize, AppendStdout, SnapshotForAttach, Exited.
type Session struct {
	sessionID string
	daemonID  string
	username  string
	userID    string

	stdin  chan []byte
	resize chan [2]uint32
	// closed is the kill switch: CloseSession closes it and the wiring
	// tears the terminal and relay down.
	closed    chan struct{}
	closeOnce sync.Once
	Stdout    chan []byte
	Exited    chan struct{}

	replayMu  sync.Mutex
	replayBuf []byte

	// lastActivity is unix nanos of the most recent stdin or stdout, for
	// the idle watcher.
	lastActivity atomic.Int64

	shutdownOnce sync.Once
}

// DaemonID returns the daemon the session runs on.
func (s *Session) DaemonID() string { return s.daemonID }

// UserID returns the user who requested the session.
func (s *Session) UserID() string { return s.userID }

func (s *Session) shutdown() {
	s.shutdownOnce.Do(func() { close(s.Exited) })
}

// Close is the kill switch for CloseSession. The wiring tears the SSH
// terminal and relay down in response.
func (s *Session) Close() {
	s.closeOnce.Do(func() { close(s.closed) })
}

func (s *Session) touch() {
	s.lastActivity.Store(time.Now().UnixNano())
}

// StartSession opens a web session: a relay to the daemon, an SSH session
// channel over it, and the wiring between the terminal and the Session the
// websocket attaches to. The session lives until the shell ends, CloseSession,
// the 8h TTL, or the idle timeout. On failure the relay slot is released and
// a typed or wrapped error is returned.
func (p *Pool) StartSession(ctx context.Context, cfg SessionConfig) (*Session, error) {
	signer, err := mintSessionCert(cfg.CA, cfg.UserID, cfg.SessionID)
	if err != nil {
		return nil, fmt.Errorf("mint session certificate: %w", err)
	}
	caKey, err := nokkussh.ParsePublicKey(cfg.CA.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse CA public key: %w", err)
	}

	relayID := uuid.NewV7().String()
	relay, err := p.RequestRelay(ctx, cfg.DaemonID, relayID, cfg.UserID)
	if err != nil {
		return nil, err
	}

	dialCtx, dialCancel := context.WithTimeout(ctx, sessionDialTime)
	defer dialCancel()
	term, err := sshclient.DialTerminal(dialCtx, NewRelayConn(relay), sshclient.Config{
		HostPrincipal: cfg.HostPrincipal,
		Username:      cfg.Username,
		Signer:        signer,
		CAKey:         caKey,
		SessionID:     cfg.SessionID,
	})
	if err != nil {
		p.UnregisterRelay(relayID)
		return nil, fmt.Errorf("ssh session: %w", err)
	}

	s := p.RegisterSession(cfg.SessionID, cfg.DaemonID, cfg.Username, cfg.UserID)

	// The TTL context is parented to the pool so a server shutdown ends
	// every session.
	sessionCtx, cancel := context.WithTimeout(p.shutdownCtx, sessionTTL)
	teardown := sync.OnceFunc(func() {
		cancel()
		term.Close()
		p.UnregisterRelay(relayID)
		p.UnregisterSession(cfg.SessionID)
		s.shutdown()
	})

	// Stdout: SSH channel output into the replay buffer and Stdout chan,
	// throttled so a chatty shell cannot flood the websocket. Its exit
	// (remote shell ended or transport died) is the session's end.
	go func() {
		limiter := rate.NewLimiter(webStdoutRate, webStdoutBurst)
		for data := range term.Stdout() {
			if err := limiter.WaitN(sessionCtx, len(data)); err != nil {
				break
			}
			s.AppendStdout(data)
			s.touch()
		}
		teardown()
		slog.Debug("web session ended", "session_id", cfg.SessionID)
	}()

	// Input: browser stdin/resize toward the terminal, plus the exit signals.
	go func() {
		defer teardown()
		idle := time.NewTicker(idleCheckEvery)
		defer idle.Stop()
		for {
			select {
			case <-sessionCtx.Done():
				return
			case <-s.Exited:
				// Killed externally: a daemon disconnect removed the session
				// from the map, or the relay died underneath the terminal.
				return
			case <-s.closed:
				return
			case data := <-s.stdin:
				s.touch()
				if _, err := term.Write(data); err != nil {
					return
				}
			case size := <-s.resize:
				if err := term.Resize(size[0], size[1]); err != nil {
					return
				}
			case <-idle.C:
				if time.Since(time.Unix(0, s.lastActivity.Load())) > sessionIdle {
					return
				}
			}
		}
	}()

	return s, nil
}

// mintSessionCert generates an ephemeral key pair and signs it as a user
// certificate for the actor. The private key dies with the request, it is
// only used for this session's handshake.
func mintSessionCert(
	ca *db.CertificateAuthority,
	principal, sessionID string,
) (ssh.Signer, error) {
	_, key, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}
	pub, err := ssh.NewPublicKey(key.Public())
	if err != nil {
		return nil, fmt.Errorf("session public key: %w", err)
	}
	cert, err := nokkussh.SignCertificate(
		ca,
		nokkussh.MarshalKey(pub),
		principal,
		"nokku:web:session:"+sessionID,
		sessionCertTTL,
		nokkuv1.SignSSHCertificateRequest_CERTIFICATE_TYPE_USER,
	)
	if err != nil {
		return nil, fmt.Errorf("sign session certificate: %w", err)
	}
	base, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, fmt.Errorf("session signer: %w", err)
	}
	return ssh.NewCertSigner(cert, base)
}

// RegisterSession inserts a session into the pool map.
func (p *Pool) RegisterSession(sessionID, daemonID, username, userID string) *Session {
	s := &Session{
		sessionID: sessionID,
		daemonID:  daemonID,
		username:  username,
		userID:    userID,
		stdin:     make(chan []byte, sendBufferSize),
		resize:    make(chan [2]uint32, sendBufferSize),
		closed:    make(chan struct{}),
		Stdout:    make(chan []byte, sendBufferSize),
		Exited:    make(chan struct{}),
	}
	s.touch()
	p.mu.Lock()
	p.sessions[sessionID] = s
	p.mu.Unlock()
	return s
}

// UnregisterSession removes a session from the pool map. The session wiring
// calls it from its teardown. Idempotent.
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
	s.Close()
}

func (s *Session) SendStdin(data []byte) {
	select {
	case s.stdin <- data:
	default:
	}
}

func (s *Session) SendResize(width, height uint32) {
	select {
	case s.resize <- [2]uint32{width, height}:
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
