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

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/db"
	nokkussh "github.com/nokku-sh/nokku/internal/ssh"
	"github.com/nokku-sh/nokku/internal/sshclient"
)

const (
	replayBufferSize = 64 * 1024
	replayTrimScan   = 256

	sessionTTL      = 8 * time.Hour
	sessionIdle     = 30 * time.Minute
	sessionDialTime = 30 * time.Second
	sessionCertTTL  = time.Hour
	idleCheckEvery  = 30 * time.Second

	// sshclient chunks at 32 KB, below the burst, so WaitN is valid.
	webStdoutRate  = 512 << 10
	webStdoutBurst = 64 << 10

	// sendTimeout closes a stalled session since dropping bytes would corrupt
	// the terminal.
	sendTimeout = 5 * time.Second
)

type SessionConfig struct {
	DaemonID  string
	SessionID string
	Username  string
	UserID    string
	CA        *db.CertificateAuthority
	// HostPrincipal is the daemon's target id.
	HostPrincipal string
}

type Session struct {
	sessionID string
	daemonID  string
	username  string
	userID    string

	stdin     chan []byte
	resize    chan [2]uint32
	closed    chan struct{}
	closeOnce sync.Once
	stdout    chan []byte
	exited    chan struct{}

	replayMu  sync.Mutex
	replayBuf []byte

	lastActivity atomic.Int64

	shutdownOnce sync.Once
}

func (s *Session) DaemonID() string { return s.daemonID }

func (s *Session) UserID() string { return s.userID }

func (s *Session) shutdown() {
	s.shutdownOnce.Do(func() { close(s.exited) })
}

func (s *Session) close() {
	s.closeOnce.Do(func() { close(s.closed) })
}

func (s *Session) touch() {
	s.lastActivity.Store(time.Now().UnixNano())
}

// StartSession lives until the shell ends, CloseSession, the TTL, or the idle
// timeout.
func (p *Pool) StartSession(ctx context.Context, cfg SessionConfig) (*Session, error) {
	if cfg.CA == nil || !cfg.CA.IsActive {
		return nil, ErrCAInactive
	}
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
	term, err := sshclient.DialTerminal(dialCtx, &relayConn{relay: relay}, sshclient.Config{
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

	s := p.registerSession(cfg.SessionID, cfg.DaemonID, cfg.Username, cfg.UserID)

	// Parented to the pool so a server shutdown ends every session.
	sessionCtx, cancel := context.WithTimeout(p.shutdownCtx, sessionTTL)
	teardown := sync.OnceFunc(func() {
		cancel()
		term.Close()
		p.UnregisterRelay(relayID)
		p.unregisterSession(cfg.SessionID)
		s.shutdown()
	})

	// Throttled so a chatty shell cannot flood the websocket. Its exit is
	// the session's end.
	go func() {
		limiter := rate.NewLimiter(webStdoutRate, webStdoutBurst)
		for data := range term.Stdout() {
			if err := limiter.WaitN(sessionCtx, len(data)); err != nil {
				break
			}
			s.appendStdout(data)
			s.touch()
		}
		teardown()
		slog.Debug("web session ended", "session_id", cfg.SessionID)
	}()

	go func() {
		defer teardown()
		idle := time.NewTicker(idleCheckEvery)
		defer idle.Stop()
		for {
			select {
			case <-sessionCtx.Done():
				return
			case <-s.exited:
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

func (p *Pool) registerSession(sessionID, daemonID, username, userID string) *Session {
	s := &Session{
		sessionID: sessionID,
		daemonID:  daemonID,
		username:  username,
		userID:    userID,
		stdin:     make(chan []byte, sendBufferSize),
		resize:    make(chan [2]uint32, sendBufferSize),
		closed:    make(chan struct{}),
		stdout:    make(chan []byte, sendBufferSize),
		exited:    make(chan struct{}),
	}
	s.touch()
	p.mu.Lock()
	p.sessions[sessionID] = s
	p.ownLocked(daemonID).sessions[sessionID] = s
	p.mu.Unlock()
	return s
}

func (p *Pool) unregisterSession(sessionID string) {
	p.mu.Lock()
	p.removeSessionLocked(sessionID)
	p.mu.Unlock()
}

func (p *Pool) removeSessionLocked(sessionID string) *Session {
	s := p.sessions[sessionID]
	if s == nil {
		return nil
	}
	delete(p.sessions, sessionID)
	if o := p.owned[s.daemonID]; o != nil {
		delete(o.sessions, sessionID)
		p.disownLocked(s.daemonID)
	}
	return s
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
	if o := p.owned[daemonID]; o != nil {
		for _, s := range o.sessions {
			result = append(result, &nokkuv1.DaemonSession{
				SessionId: new(s.sessionID),
				Username:  new(s.username),
				UserId:    new(s.userID),
			})
		}
	}
	return result
}

func (p *Pool) CloseSession(sessionID string) {
	p.mu.Lock()
	s := p.removeSessionLocked(sessionID)
	p.mu.Unlock()
	if s == nil {
		return
	}
	s.shutdown()
	s.close()
}

func (s *Session) SendStdin(data []byte) {
	select {
	case s.stdin <- data:
	case <-s.closed:
	case <-time.After(sendTimeout):
		slog.Warn("terminal stdin buffer full, closing session", "session_id", s.sessionID)
		s.close()
	}
}

func (s *Session) SendResize(width, height uint32) {
	select {
	case s.resize <- [2]uint32{width, height}:
	case <-s.closed:
	case <-time.After(sendTimeout):
		slog.Warn("terminal resize buffer full, closing session", "session_id", s.sessionID)
		s.close()
	}
}

func (s *Session) appendStdout(data []byte) {
	s.replayMu.Lock()
	s.replayBuf = append(s.replayBuf, data...)
	if len(s.replayBuf) > replayBufferSize*2 {
		s.trimReplayLocked()
	}
	// Send under replayMu so SnapshotForAttach never sees a chunk both in the
	// replay and still queued, which would render it twice.
	select {
	case s.stdout <- data:
	case <-s.closed:
	case <-time.After(sendTimeout):
		slog.Warn("terminal stdout buffer full, closing session", "session_id", s.sessionID)
		s.close()
	}
	s.replayMu.Unlock()
}

// SnapshotForAttach strips terminal queries from the replay, or a fresh
// terminal would answer them into the session's stdin.
func (s *Session) SnapshotForAttach() (replay []byte, live <-chan []byte) {
	s.replayMu.Lock()
	raw := append([]byte(nil), s.replayBuf...)
	// Queued chunks are already in the replay.
drain:
	for {
		select {
		case <-s.stdout:
		default:
			break drain
		}
	}
	s.replayMu.Unlock()
	return sanitizeReplay(raw), s.stdout
}

// trimReplayLocked cuts at a safe sequence boundary when one is close.
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
	s.replayBuf = append([]byte(nil), s.replayBuf[excess:]...)
}

func (s *Session) Exited() <-chan struct{} { return s.exited }
