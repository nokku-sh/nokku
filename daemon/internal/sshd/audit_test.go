package sshd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestServerAuditEvents(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	log, events := auditLog()
	addr, closeFn := startTestServerOpts(t, ca, Options{Log: log})
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

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// A valid certificate signed with another key, like a client that copied a cert without the private key.
type wrongKeySigner struct {
	cert  ssh.PublicKey
	other ssh.Signer
}

func (w wrongKeySigner) PublicKey() ssh.PublicKey { return w.cert }

func (w wrongKeySigner) Sign(r io.Reader, data []byte) (*ssh.Signature, error) {
	return w.other.Sign(r, data)
}

func TestServerAuditNoSuccessWithoutKey(t *testing.T) {
	must := require.New(t)
	ca := newTestCA(t)
	log, events := auditLog()
	addr, closeFn := startTestServerOpts(t, ca, Options{Log: log})
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
	addr, closeFn := startTestServerOpts(t, ca, Options{Log: log, Policy: DefaultPolicy})
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
