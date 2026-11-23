package sshd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/time/rate"

	"github.com/nokku-sh/nokku/daemon/internal/report"
)

// fakeMeta is a connection before its key proof, the only parts a refused login reads.
type fakeMeta struct {
	ssh.ConnMetadata

	user string
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

// A valid cert signed with another key, like a copied cert without its key.
type wrongKeySigner struct {
	cert  ssh.PublicKey
	other ssh.Signer
}

type versionLine struct {
	ssh.ConnMetadata

	line string
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

func (v versionLine) ClientVersion() []byte { return []byte(v.line) }

// The client picks its version line, and it goes into the log and the login report.
func TestClientVersionKeepsOnlyWhatPrints(t *testing.T) {
	for in, want := range map[string]string{
		"SSH-2.0-OpenSSH_10.0":        "SSH-2.0-OpenSSH_10.0",
		"SSH-2.0-nul\x00here":         "SSH-2.0-nulhere",
		"SSH-2.0-bad\xffbyte":         "SSH-2.0-badbyte",
		"SSH-2.0-line\nfake=1\x1b[0m": "SSH-2.0-linefake=1[0m",
		"SSH-2.0-Größe":               "SSH-2.0-Größe",
	} {
		assert.Equal(t, want, clientVersion(versionLine{line: in}), "%q", in)
	}
}

func (f fakeMeta) User() string         { return f.user }
func (f fakeMeta) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4022} }

// Anyone who reaches the port can cause a refused login, so their lines are capped and the next one says how many
// went unlogged.
func TestRefusedLoginsAreCapped(t *testing.T) {
	log, events := auditLog()
	s := &Server{log: log, refused: rate.NewLimiter(rate.Every(time.Hour), 3)}
	conn := versionLine{ConnMetadata: fakeMeta{user: strings.Repeat("x", 4096)}, line: "SSH-2.0-flood"}
	for range 10 {
		_ = s.deny(conn, errors.New("refused"))
	}
	assert.Len(t, events(), 3, "the burst passes, the rest is held back")

	s.refused = rate.NewLimiter(rate.Inf, 1)
	_ = s.deny(conn, errors.New("refused"))
	assert.Equal(t, []eventType{
		eventAuthFailure, eventAuthFailure, eventAuthFailure, eventAuthFailuresUnlogged, eventAuthFailure,
	}, events())
}

func TestPrintableCutsALongClientField(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "root", printable("root"))
	long := printable(strings.Repeat("é", 200))
	assert.LessOrEqual(t, len(long), maxClientField+len("…"))
	assert.True(t, utf8.ValidString(long), "a cut in the middle of a rune")
	assert.Equal(t, "ab", printable("a\x1b\nb"), "control characters reach the log")
}
