// Package sshtest is an in-process SSH server for tests. It presents a host
// certificate signed by a test CA, authenticates user certificates the same
// way the daemon's sshd does, records session requests, and echoes stdin
// back after the shell request.
package sshtest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
	nokkussh "github.com/nokku-sh/nokku/internal/ssh"
	"github.com/nokku-sh/nokku/internal/util"
)

// Server is a running test SSH server.
type Server struct {
	// UserPrincipal is the cert principal the server accepts, standing in
	// for the uuid list the daemon's sshd syncs for an OS user.
	UserPrincipal string
	// HostPrincipal is the principal carried by the host certificate,
	// standing in for the daemon's target id.
	HostPrincipal string

	mu            sync.Mutex
	env           map[string]string
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

// NewServer starts a test SSH server on 127.0.0.1.
func NewServer(t testing.TB) *Server {
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
		ValidPrincipals: []string{"target-1"},
		ValidAfter:      util.UnixTimeToUint64(time.Now().Add(-time.Minute).Unix()),
		ValidBefore:     util.UnixTimeToUint64(time.Now().Add(time.Hour).Unix()),
	}
	if err := hostCert.SignCert(crand.Reader, caSigner); err != nil {
		t.Fatalf("sign host cert: %v", err)
	}
	hostSigner, err := ssh.NewCertSigner(hostCert, mustSigner(t, hostPriv))
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	s := &Server{
		UserPrincipal: "u1",
		HostPrincipal: "target-1",
		env:           make(map[string]string),
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

// Addr returns the server's TCP address.
func (s *Server) Addr() string { return s.listener.Addr().String() }

// CAKey returns the CA public key clients must pin for host verification.
func (s *Server) CAKey() ssh.PublicKey { return s.ca.PublicKey() }

// CA returns the server's CA in the row form the api layer loads, so
// callers exercise the real certificate-minting path.
func (s *Server) CA(t testing.TB) *db.CertificateAuthority {
	t.Helper()
	return caRow(t, s.caPriv)
}

// NewCA generates a CA row no server trusts, for handshake-failure tests.
func NewCA(t testing.TB) *db.CertificateAuthority {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	return caRow(t, priv)
}

func caRow(t testing.TB, priv ed25519.PrivateKey) *db.CertificateAuthority {
	t.Helper()
	privPEM, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal CA private key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("CA signer: %v", err)
	}
	return &db.CertificateAuthority{
		PrivateKey:     crypto.EncryptedBytes(pem.EncodeToMemory(privPEM)),
		PublicKey:      nokkussh.MarshalKey(signer.PublicKey()),
		UserDefaultTtl: time.Hour,
		UserMaxTtl:     24 * time.Hour,
		UserExtensions: []byte(
			`{"permit-pty":"","permit-port-forwarding":"","permit-agent-forwarding":""}`,
		),
		IsActive: true,
	}
}

// UserSigner mints a user certificate signed by the test CA.
func (s *Server) UserSigner(t testing.TB, principal string) ssh.Signer {
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
		ValidPrincipals: []string{principal},
		ValidAfter:      util.UnixTimeToUint64(time.Now().Add(-time.Minute).Unix()),
		ValidBefore:     util.UnixTimeToUint64(time.Now().Add(time.Hour).Unix()),
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

// Env returns an environment variable sent by the client.
func (s *Server) Env(name string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.env[name]
}

// Pty returns the recorded terminal size.
func (s *Server) Pty() (term string, cols, rows uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ptyTerm, s.ptyCols, s.ptyRows
}

// WindowChanges returns the recorded window-change sizes.
func (s *Server) WindowChanges() []struct{ Cols, Rows uint32 } {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.windowChanges)
}

// ConnUser returns the username the client connected with.
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
			if !slices.Contains(cert.ValidPrincipals, s.UserPrincipal) {
				return nil, errors.New("principal not authorized")
			}
			s.mu.Lock()
			s.connUser = conn.User()
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
		case "env":
			var e struct{ Name, Value string }
			if ssh.Unmarshal(req.Payload, &e) != nil {
				_ = req.Reply(false, nil)
				continue
			}
			s.mu.Lock()
			s.env[e.Name] = e.Value
			s.mu.Unlock()
			_ = req.Reply(true, nil)
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

func echo(ch ssh.Channel) {
	defer func() { _ = ch.Close() }()
	_, _ = io.Copy(ch, ch)
}

func mustSigner(t testing.TB, priv ed25519.PrivateKey) ssh.Signer {
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer
}
