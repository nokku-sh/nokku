package sshd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"maps"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokku/daemon/internal/report"
)

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

// A valid cert signed with another key, like a copied cert without its key.
type wrongKeySigner struct {
	cert  ssh.PublicKey
	other ssh.Signer
}

func TestServerAuditEvents(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	log, events := auditLog()
	addr, closeFn := startTestServerOpts(t, ca, withLog(log))
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err)
	sess, err := client.NewSession()
	must.NoError(err)
	out, err := sess.Output("echo hi")
	must.NoError(err)
	is.Equal("hi\n", string(out))
	_ = sess.Close()
	_ = client.Close()

	_, err = dial(t, addr, currentUser(t), userCert(t, ca, "some-other-principal"))
	must.Error(err, "login with wrong principal unexpectedly succeeded")

	// session_end is logged when the server has torn the session down.
	for _, want := range []eventType{
		eventAuthSuccess,
		eventAuthFailure,
		eventSessionStart,
		eventSessionEnd,
		eventCommand,
	} {
		is.Eventually(func() bool { return slices.Contains(events(), want) },
			5*time.Second, 20*time.Millisecond, "missing audit event %q in %v", want, events())
	}
}

func auditLog() (*slog.Logger, func() []eventType) {
	var mu sync.Mutex
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(lockedWriter{mu: &mu, w: &buf}, nil))
	return log, func() []eventType {
		mu.Lock()
		defer mu.Unlock()
		var types []eventType
		for line := range bytes.Lines(buf.Bytes()) {
			var rec struct {
				Msg  string    `json:"msg"`
				Type eventType `json:"type"`
			}
			if json.Unmarshal(line, &rec) == nil && rec.Msg == "audit" {
				types = append(types, rec.Type)
			}
		}
		return types
	}
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func (w wrongKeySigner) PublicKey() ssh.PublicKey { return w.cert }

func (w wrongKeySigner) Sign(r io.Reader, data []byte) (*ssh.Signature, error) {
	return w.other.Sign(r, data)
}

func TestServerAuditNoSuccessWithoutKey(t *testing.T) {
	must := require.New(t)
	ca := newTestCA(t)
	log, events := auditLog()
	addr, closeFn := startTestServerOpts(t, ca, withLog(log))
	defer closeFn()

	newSigner := func() (ssh.PublicKey, ssh.Signer) {
		_, priv, keyErr := ed25519.GenerateKey(rand.Reader)
		must.NoError(keyErr)
		signer, keyErr := ssh.NewSignerFromKey(priv)
		must.NoError(keyErr)
		return signer.PublicKey(), signer
	}
	pub, _ := newSigner()
	cert := &ssh.Certificate{
		Key:             pub,
		CertType:        ssh.UserCert,
		ValidPrincipals: []string{testPrincipal},
		ValidBefore:     ssh.CertTimeInfinity,
		Extensions:      maps.Clone(defaultExtensions),
	}
	must.NoError(cert.SignCert(rand.Reader, ca.signer))
	_, other := newSigner()

	_, err := dial(t, addr, currentUser(t), ssh.PublicKeys(wrongKeySigner{cert: cert, other: other}))
	must.Error(err, "login without the private key unexpectedly succeeded")

	assert.NotContains(t, events(), eventAuthSuccess)
}

func TestServerAuditFileTransferAndRemoteForward(t *testing.T) {
	must := require.New(t)
	ca := newTestCA(t)
	log, events := auditLog()
	addr, closeFn := startTestServerOpts(t, ca, withLog(log), withPolicy(defaultPolicy))
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err)
	defer client.Close()

	sc, err := sftp.NewClient(client)
	must.NoError(err)
	_, err = sc.Getwd()
	must.NoError(err)
	_ = sc.Close()

	ln, err := client.Listen("tcp", "127.0.0.1:0")
	must.NoError(err)
	_ = ln.Close()

	_ = client.Close()
	assert.Contains(t, events(), eventSubsystem)
	assert.Contains(t, events(), eventRemoteForward)
}

// Every connection is put down for the core twice, when it opens and when it is gone.
func TestConnectionIsReported(t *testing.T) {
	ca := newTestCA(t)
	spool := report.Open(filepath.Join(t.TempDir(), "connections.jsonl"))
	addr, closeFn := startTestServerOpts(t, ca, func(s *Server) { s.reports = spool })
	defer closeFn()

	_, err := dial(t, addr, currentUser(t), userCert(t, ca, "some-other-principal"))
	require.Error(t, err)
	events, _ := spool.Next()
	require.Empty(t, events, "a refused login is no connection")

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	require.NoError(t, err)
	require.Eventually(t, func() bool { events, _ = spool.Next(); return len(events) == 1 },
		5*time.Second, 10*time.Millisecond, "the login was not put down")
	opened := events[0]
	assert.False(t, opened.Closed)
	assert.Equal(t, testPrincipal, opened.Principal)
	assert.Equal(t, "test-user", opened.KeyID, "the key id the CA signed")
	assert.Equal(t, client.LocalAddr().String(), opened.Remote)
	assert.NotEmpty(t, opened.Client)
	assert.WithinDuration(t, time.Now(), opened.Time, time.Minute)

	require.NoError(t, client.Close())
	require.Eventually(t, func() bool { events, _ = spool.Next(); return len(events) == 2 },
		5*time.Second, 10*time.Millisecond, "the end of the connection was not put down")
	assert.True(t, events[1].Closed)
	assert.Equal(t, opened.ConnectionID, events[1].ConnectionID, "both ends go by one id")
}
