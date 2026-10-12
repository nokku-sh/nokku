package daemon

import (
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"fmt"
	"sync"
	"time"
	"uuid"

	"golang.org/x/crypto/ssh"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/db"
	nokkussh "github.com/nokku-sh/nokku/internal/ssh"
	"github.com/nokku-sh/nokku/internal/sshclient"
)

const (
	sessionTTL      = 8 * time.Hour
	sessionDialTime = 30 * time.Second
	sessionCertTTL  = time.Hour
)

type SessionConfig struct {
	DaemonID  string
	SessionID string
	Username  string
	UserID    string
	CA        *db.SSHCA
	// HostPrincipal is the daemon's target id.
	HostPrincipal string
	// ClientAddr is the browser's address, reported to the daemon's sshd.
	ClientAddr string
}

// Session is one browser terminal. It belongs to the websocket that started it.
type Session struct {
	sessionID string
	daemonID  string
	username  string
	userID    string

	term  *sshclient.Terminal
	close func()
}

func (s *Session) DaemonID() string { return s.daemonID }

// Stdout is closed when the session ends.
func (s *Session) Stdout() <-chan []byte { return s.term.Stdout() }

func (s *Session) Write(data []byte) error {
	_, err := s.term.Write(data)
	return err
}

func (s *Session) Resize(width, height uint32) error {
	return s.term.Resize(width, height)
}

// Exited reports whether the shell ended on its own. It is final once Stdout is closed.
func (s *Session) Exited() bool { return s.term.Exited() }

// Close is idempotent.
func (s *Session) Close() { s.close() }

// StartSession lives until ctx ends, the shell ends, the daemon drops, Close, or the TTL.
func (p *Pool) StartSession(ctx context.Context, cfg SessionConfig) (*Session, error) {
	if cfg.CA == nil || !cfg.CA.IsActive {
		return nil, ErrCAInactive
	}
	principal := nokkussh.LoginPrincipal(cfg.UserID, cfg.HostPrincipal, cfg.Username)
	signer, err := mintSessionCert(cfg.CA, principal, cfg.SessionID)
	if err != nil {
		return nil, fmt.Errorf("mint session certificate: %w", err)
	}
	caKey, err := nokkussh.ParsePublicKey(cfg.CA.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse CA public key: %w", err)
	}

	relayID := uuid.NewV7().String()
	relay, err := p.RequestRelay(ctx, cfg.DaemonID, relayID, cfg.UserID, cfg.ClientAddr)
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
	})
	if err != nil {
		p.UnregisterRelay(relayID)
		return nil, fmt.Errorf("ssh session: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, sessionTTL)
	s := &Session{
		sessionID: cfg.SessionID,
		daemonID:  cfg.DaemonID,
		username:  cfg.Username,
		userID:    cfg.UserID,
		term:      term,
	}
	s.close = sync.OnceFunc(func() {
		cancel()
		term.Close()
		p.UnregisterRelay(relayID)
		p.mu.Lock()
		if p.sessions[s.sessionID] == s {
			delete(p.sessions, s.sessionID)
		}
		if o := p.owned[s.daemonID]; o != nil && o.sessions[s.sessionID] == s {
			delete(o.sessions, s.sessionID)
			p.disownLocked(s.daemonID)
		}
		p.mu.Unlock()
	})

	p.mu.Lock()
	p.sessions[s.sessionID] = s
	p.ownLocked(s.daemonID).sessions[s.sessionID] = s
	p.mu.Unlock()
	context.AfterFunc(ctx, s.close)
	return s, nil
}

func mintSessionCert(
	ca *db.SSHCA,
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
		[]string{principal},
		"nokku:web:session:"+sessionID,
		sessionCertTTL,
		ssh.UserCert,
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
