package daemon

import (
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"fmt"
	"slices"
	"sync"
	"time"
	"uuid"

	"golang.org/x/crypto/ssh"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/login"

	"github.com/nokku-sh/nokku/core/internal/db"
	nokkussh "github.com/nokku-sh/nokku/core/internal/ssh"
	"github.com/nokku-sh/nokku/core/internal/sshclient"
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
	// HostCA is the CA host key, the daemon's host certificate must come from it.
	HostCA string
	// Signer holds the certificate from MintSessionCert.
	Signer ssh.Signer
	// HostPrincipal is the daemon's target id.
	HostPrincipal string
	// ClientAddr is the browser's address, reported to the daemon's sshd.
	ClientAddr string
}

// Session is one browser terminal. It belongs to the websocket that started it.
type Session struct {
	sessionID string
	username  string

	term  *sshclient.Terminal
	close func()
}

// Stdout is closed when the session ends.
func (s *Session) Stdout() <-chan []byte { return s.term.Stdout() }

func (s *Session) Write(data []byte) error {
	_, err := s.term.Write(data)
	return err
}

func (s *Session) Resize(width, height uint32) error {
	return s.term.Resize(width, height)
}

// Exited is whether the shell ended itself, final once Stdout is closed.
func (s *Session) Exited() bool { return s.term.Exited() }

// Close is idempotent.
func (s *Session) Close() { s.close() }

// StartSession ends with ctx, the shell, the daemon, Close or the TTL.
func (p *Pool) StartSession(ctx context.Context, cfg SessionConfig) (*Session, error) {
	hostCA, err := nokkussh.ParsePublicKey(cfg.HostCA)
	if err != nil {
		return nil, fmt.Errorf("parse host CA public key: %w", err)
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
		Signer:        cfg.Signer,
		HostCA:        hostCA,
	})
	if err != nil {
		p.UnregisterRelay(relayID)
		return nil, fmt.Errorf("ssh session: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, sessionTTL)
	s := &Session{
		sessionID: cfg.SessionID,
		username:  cfg.Username,
		term:      term,
	}
	s.close = sync.OnceFunc(func() {
		cancel()
		term.Close()
		p.UnregisterRelay(relayID)
	})

	p.mu.Lock()
	relay.shell = s
	p.mu.Unlock()
	context.AfterFunc(ctx, s.close)
	return s, nil
}

// MintSessionCert signs a key for one browser terminal. caSigner is CA's user key.
func MintSessionCert(
	ca *db.SSHCA,
	caSigner ssh.Signer,
	principal, sessionID string,
) (ssh.Signer, *ssh.Certificate, error) {
	_, key, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate session key: %w", err)
	}
	pub, err := ssh.NewPublicKey(key.Public())
	if err != nil {
		return nil, nil, fmt.Errorf("session public key: %w", err)
	}
	cert, err := nokkussh.SignCertificate(
		ca,
		caSigner,
		nokkussh.MarshalKey(pub),
		[]string{principal},
		login.WebSessionKeyIDPrefix+sessionID,
		sessionCertTTL,
		ssh.UserCert,
		nokkussh.Limits{SourceAddress: ca.SourceAddress},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("sign session certificate: %w", err)
	}
	base, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("session signer: %w", err)
	}
	signer, err := ssh.NewCertSigner(cert, base)
	return signer, cert, err
}

// SessionDaemons names the daemons with an open terminal, in every workspace.
func (p *Pool) SessionDaemons() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var ids []string
	for _, r := range p.relays {
		if r.shell != nil && !slices.Contains(ids, r.daemonID) {
			ids = append(ids, r.daemonID)
		}
	}
	return ids
}

func (p *Pool) ListSessions(daemonID string) []*nokkuv1.DaemonSession {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var result []*nokkuv1.DaemonSession
	for _, r := range p.relays {
		if s := r.shell; s != nil && r.daemonID == daemonID {
			result = append(result, &nokkuv1.DaemonSession{
				SessionId: new(s.sessionID),
				Username:  new(s.username),
				UserId:    new(r.userID),
			})
		}
	}
	return result
}
