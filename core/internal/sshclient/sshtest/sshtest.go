// Package sshtest is an in-process SSH server for tests. It authenticates like the daemon's sshd and echoes stdin.
package sshtest

import (
	"bytes"
	"crypto/ed25519"
	crand "crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokku/core/internal/crypto"
	"github.com/nokku-sh/nokku/core/internal/db"
	nokkussh "github.com/nokku-sh/nokku/core/internal/ssh"
)

type Server struct {
	// UserPrincipal is the one subject the server lets in, as any account.
	UserPrincipal string
	// HostPrincipal stands in for the daemon's target id.
	HostPrincipal string

	mu            sync.Mutex
	keyID         string
	shellStarted  bool
	ptyTerm       string
	ptyCols       uint32
	ptyRows       uint32
	windowChanges []struct{ Cols, Rows uint32 }
	connUser      string

	ca        ssh.Signer
	caPriv    ed25519.PrivateKey
	hostKey   ssh.Signer
	listener  net.Listener
	conns     map[net.Conn]struct{}
	connsMu   sync.Mutex
	closeOnce sync.Once
}

func NewServer(t testing.TB) *Server {
	t.Helper()
	return NewServerFor(t, "target-1", "u1")
}

// NewServerFor is for tests that run against real target and user ids.
func NewServerFor(t testing.TB, hostPrincipal, userPrincipal string) *Server {
	t.Helper()
	_, caPriv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatalf("CA signer: %v", err)
	}

	hostPub, hostPriv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	hostSSHKey, err := ssh.NewPublicKey(hostPub)
	if err != nil {
		t.Fatalf("host public key: %v", err)
	}
	hostCert := &ssh.Certificate{
		Key:             hostSSHKey,
		CertType:        ssh.HostCert,
		KeyId:           "sshtest-host",
		ValidPrincipals: []string{hostPrincipal},
		ValidAfter:      nokkussh.UnixUint64(time.Now().Add(-time.Minute).Unix()),
		ValidBefore:     nokkussh.UnixUint64(time.Now().Add(time.Hour).Unix()),
	}
	if err := hostCert.SignCert(crand.Reader, caSigner); err != nil {
		t.Fatalf("sign host cert: %v", err)
	}
	hostSigner, err := ssh.NewCertSigner(hostCert, mustSigner(t, hostPriv))
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	s := &Server{
		UserPrincipal: userPrincipal,
		HostPrincipal: hostPrincipal,
		ca:            caSigner,
		caPriv:        caPriv,
		hostKey:       hostSigner,
		listener:      ln,
		conns:         make(map[net.Conn]struct{}),
	}
	go s.serve()
	t.Cleanup(s.Close)
	return s
}

func (s *Server) Addr() string { return s.listener.Addr().String() }

func (s *Server) CAKey() ssh.PublicKey { return s.ca.PublicKey() }

// CA returns a row so callers exercise the real cert-minting path.
func (s *Server) CA(t testing.TB) *db.SSHCA {
	t.Helper()
	return caRow(t, s.caPriv)
}

// NewCA generates a CA row no server trusts, for handshake-failure tests.
func NewCA(t testing.TB) *db.SSHCA {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	return caRow(t, priv)
}

func caRow(t testing.TB, priv ed25519.PrivateKey) *db.SSHCA {
	t.Helper()
	privPEM, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal CA private key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("CA signer: %v", err)
	}
	return &db.SSHCA{
		PrivateKey:     crypto.EncryptedBytes(pem.EncodeToMemory(privPEM)),
		PublicKey:      nokkussh.MarshalKey(signer.PublicKey()),
		UserDefaultTtl: time.Hour,
		UserMaxTtl:     24 * time.Hour,
		IsActive:       true,
	}
}

// UserSigner is a certificate for subject to log in as username, the way the backend signs one.
func (s *Server) UserSigner(t testing.TB, subject, username string) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("generate user key: %v", err)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("user public key: %v", err)
	}
	cert := &ssh.Certificate{
		Key:             pub,
		CertType:        ssh.UserCert,
		KeyId:           "sshtest-user",
		ValidPrincipals: []string{nokkussh.LoginPrincipal(subject, s.HostPrincipal, username)},
		ValidAfter:      nokkussh.UnixUint64(time.Now().Add(-time.Minute).Unix()),
		ValidBefore:     nokkussh.UnixUint64(time.Now().Add(time.Hour).Unix()),
		Extensions: map[string]string{
			"permit-pty":              "",
			"permit-port-forwarding":  "",
			"permit-agent-forwarding": "",
		},
	}
	if err := cert.SignCert(crand.Reader, s.ca); err != nil {
		t.Fatalf("sign user cert: %v", err)
	}
	base, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("user signer: %v", err)
	}
	signer, err := ssh.NewCertSigner(cert, base)
	if err != nil {
		t.Fatalf("cert signer: %v", err)
	}
	return signer
}

// KeyID is the key id of the certificate the last login presented.
func (s *Server) KeyID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keyID
}

// ShellStarted reports whether a session asked for its shell.
func (s *Server) ShellStarted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.shellStarted
}

func (s *Server) Pty() (term string, cols, rows uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ptyTerm, s.ptyCols, s.ptyRows
}

func (s *Server) WindowChanges() []struct{ Cols, Rows uint32 } {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.windowChanges)
}

func (s *Server) ConnUser() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connUser
}

func (s *Server) Close() {
	s.closeOnce.Do(func() {
		_ = s.listener.Close()
		s.connsMu.Lock()
		for c := range s.conns {
			_ = c.Close()
		}
		s.connsMu.Unlock()
	})
}

func (s *Server) serve() {
	for {
		c, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.connsMu.Lock()
		s.conns[c] = struct{}{}
		s.connsMu.Unlock()
		go func() {
			defer func() {
				s.connsMu.Lock()
				delete(s.conns, c)
				s.connsMu.Unlock()
			}()
			s.handle(c)
		}()
	}
}

func (s *Server) handle(c net.Conn) {
	cfg := &ssh.ServerConfig{
		//nolint:gosec // test server, the callback is self-contained and synchronous.
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			cert, ok := key.(*ssh.Certificate)
			if !ok || cert.CertType != ssh.UserCert {
				return nil, errors.New("expected a user certificate")
			}
			if !bytes.Equal(cert.SignatureKey.Marshal(), s.ca.PublicKey().Marshal()) {
				return nil, errors.New("certificate not signed by the test CA")
			}
			want := nokkussh.LoginPrincipal(s.UserPrincipal, s.HostPrincipal, conn.User())
			if !slices.Contains(cert.ValidPrincipals, want) {
				return nil, errors.New("principal not authorized")
			}
			s.mu.Lock()
			s.connUser = conn.User()
			s.keyID = cert.KeyId
			s.mu.Unlock()
			return &ssh.Permissions{
				Extensions: map[string]string{"nokku-principal": s.UserPrincipal},
			}, nil
		},
	}
	cfg.AddHostKey(s.hostKey)

	conn, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	go s.globalReqs(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		go s.handleSession(newCh)
	}
}

// globalReqs answers keepalives like the daemon's sshd does.
func (s *Server) globalReqs(reqs <-chan *ssh.Request) {
	for req := range reqs {
		if req.Type == "keepalive@openssh.com" && req.WantReply {
			_ = req.Reply(true, nil)
			continue
		}
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
	}
}

func (s *Server) handleSession(newCh ssh.NewChannel) {
	ch, reqs, err := newCh.Accept()
	if err != nil {
		return
	}
	for req := range reqs {
		switch req.Type {
		case "pty-req":
			var p struct {
				Term     string
				Columns  uint32
				Rows     uint32
				WidthPx  uint32
				HeightPx uint32
				Modes    []byte
			}
			if ssh.Unmarshal(req.Payload, &p) != nil {
				_ = req.Reply(false, nil)
				continue
			}
			s.mu.Lock()
			s.ptyTerm, s.ptyCols, s.ptyRows = p.Term, p.Columns, p.Rows
			s.mu.Unlock()
			_ = req.Reply(true, nil)
		case "shell":
			s.mu.Lock()
			s.shellStarted = true
			s.mu.Unlock()
			_ = req.Reply(true, nil)
			go echo(ch)
		case "window-change":
			var w struct{ Columns, Rows, WidthPx, HeightPx uint32 }
			if ssh.Unmarshal(req.Payload, &w) != nil {
				_ = req.Reply(false, nil)
				continue
			}
			s.mu.Lock()
			s.windowChanges = append(s.windowChanges, struct{ Cols, Rows uint32 }{w.Columns, w.Rows})
			s.mu.Unlock()
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

// echo is the fake shell. Ctrl+D ends it with exit status 0, like a real one.
func echo(ch ssh.Channel) {
	defer func() { _ = ch.Close() }()
	buf := make([]byte, 1024)
	for {
		n, err := ch.Read(buf)
		if bytes.IndexByte(buf[:n], 0x04) >= 0 {
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			return
		}
		if _, werr := ch.Write(buf[:n]); werr != nil || err != nil {
			return
		}
	}
}

func mustSigner(t testing.TB, priv ed25519.PrivateKey) ssh.Signer {
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer
}
