package sshd

import (
	"crypto/ed25519"
	"crypto/rand"
	"maps"
	"net"
	"os"
	"os/user"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/nokkud/internal/paths"
	"github.com/nokku-sh/nokku/nokkud/internal/state"
)

const testPrincipal = "9a3c2a0f-5f1e-4a7b-9c4d-2e6b8f0a1c3d"

type testCA struct {
	pub    ssh.PublicKey
	signer ssh.Signer
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err, "generate CA")
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err, "CA signer")
	pub, err := ssh.NewPublicKey(priv.Public())
	require.NoError(t, err, "CA public key")
	return testCA{pub: pub, signer: signer}
}

func userCert(t *testing.T, ca testCA, principals ...string) ssh.AuthMethod {
	t.Helper()
	return userCertOpts(t, ca, nil, principals...)
}

// The backend's default cert template. The daemon enforces permit-*, so tests grant them explicitly.
var defaultExtensions = map[string]string{
	"permit-pty":              "",
	"permit-user-rc":          "",
	"permit-port-forwarding":  "",
	"permit-agent-forwarding": "",
}

func userCertOpts(
	t *testing.T,
	ca testCA,
	opts func(*ssh.Certificate),
	principals ...string,
) ssh.AuthMethod {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err, "generate user key")
	userSigner, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err, "user signer")
	pub, err := ssh.NewPublicKey(priv.Public())
	require.NoError(t, err, "user public key")
	cert := &ssh.Certificate{
		Key:             pub,
		CertType:        ssh.UserCert,
		KeyId:           "test-user",
		ValidPrincipals: principals,
		ValidAfter:      0,
		ValidBefore:     ssh.CertTimeInfinity,
		Extensions:      maps.Clone(defaultExtensions),
	}
	if opts != nil {
		opts(cert)
	}
	require.NoError(t, cert.SignCert(rand.Reader, ca.signer), "sign cert")
	certSigner, err := ssh.NewCertSigner(cert, userSigner)
	require.NoError(t, err, "cert signer")
	return ssh.PublicKeys(certSigner)
}

// The default principals allow testPrincipal for the current user only.
func startTestServer(t *testing.T, ca testCA) (addr string, closeFn func()) {
	t.Helper()
	return startTestServerOpts(t, ca, Options{})
}

func startTestServerOpts(
	t *testing.T,
	ca testCA,
	extra Options,
	tweaks ...func(*Server),
) (addr string, closeFn func()) {
	t.Helper()
	cur, err := user.Current()
	require.NoError(t, err, "current user")
	principals := func(username string) []string {
		if username == cur.Username {
			return []string{testPrincipal}
		}
		return nil
	}

	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
	extra.Principals = principals
	srv, err := New(extra)
	require.NoError(t, err, "new server")
	srv.SetTrust(string(ssh.MarshalAuthorizedKey(ca.pub)), nil)
	for _, tweak := range tweaks {
		tweak(srv)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "listen")
	go srv.Serve(t.Context(), l)
	return l.Addr().String(), func() { _ = l.Close() }
}

func dial(t *testing.T, addr, username string, auth ssh.AuthMethod) (*ssh.Client, error) {
	t.Helper()
	cfg := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // #nosec G106 - test server
		Timeout:         10 * time.Second,
	}
	return ssh.Dial("tcp", addr, cfg)
}

func TestServerExec(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	sess, err := client.NewSession()
	must.NoError(err, "new session")
	defer sess.Close()

	out, err := sess.Output("printf hello-nokkud")
	must.NoError(err, "exec")
	is.Equal("hello-nokkud", string(out))
}

func TestServerExecExitStatus(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	sess, err := client.NewSession()
	must.NoError(err, "new session")
	defer sess.Close()

	err = sess.Run("exit 7")
	var ee *ssh.ExitError
	must.ErrorAs(err, &ee)
	is.Equal(7, ee.ExitStatus())
}

func TestServerExecExitSignal(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	sess, err := client.NewSession()
	must.NoError(err, "new session")
	defer sess.Close()

	// The command kills its own shell, so the server reports exit-signal and the Go client maps it to 128+signal.
	err = sess.Run("kill -TERM $$")
	var ee *ssh.ExitError
	must.ErrorAs(err, &ee)
	is.Equal("TERM", ee.Signal())
	is.Equal(143, ee.ExitStatus())
}

func TestServerPTYExec(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	sess, err := client.NewSession()
	must.NoError(err, "new session")
	defer sess.Close()

	must.NoError(sess.RequestPty("xterm-256color", 80, 24, ssh.TerminalModes{}), "request pty")
	out, err := sess.Output("printf pty-ok")
	must.NoError(err, "pty exec")
	is.Equal("pty-ok", string(out))
}

// A client without TERM sends an empty one, which must not replace the default.
func TestServerPTYEmptyTerm(t *testing.T) {
	must := require.New(t)
	// Setenv restores the value after the test, Unsetenv takes it away for it.
	t.Setenv("TERM", "")
	must.NoError(os.Unsetenv("TERM"))

	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	sess, err := client.NewSession()
	must.NoError(err, "new session")
	defer sess.Close()

	must.NoError(sess.RequestPty("", 80, 24, ssh.TerminalModes{}), "request pty")
	out, err := sess.Output("printf %s \"$TERM\"")
	must.NoError(err, "pty exec")
	must.Equal("xterm-256color", string(out))
}

func TestServerDeniesUntrustedCA(t *testing.T) {
	is := assert.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	other := newTestCA(t)
	_, err := dial(t, addr, currentUser(t), userCert(t, other, testPrincipal))
	is.Error(err, "expected auth to fail with untrusted CA")
}

func TestServerDeniesWrongPrincipal(t *testing.T) {
	is := assert.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	_, err := dial(t, addr, currentUser(t), userCert(t, ca, "unknown-principal"))
	is.Error(err, "expected auth to fail with unauthorized principal")
}

// The principal is compared as a whole, so one for another server or account opens nothing.
func TestServerDeniesCertificateOfAnotherServerOrAccount(t *testing.T) {
	ca := newTestCA(t)
	cur := currentUser(t)
	here := "subject@this-server:" + cur
	addr, closeFn := startTestServerOpts(t, ca, Options{}, func(s *Server) {
		s.principals = func(username string) []string {
			if username == cur {
				return []string{here}
			}
			return nil
		}
	})
	defer closeFn()

	for _, principal := range []string{"subject@other-server:" + cur, "subject@this-server:other", "subject"} {
		_, err := dial(t, addr, cur, userCert(t, ca, principal))
		require.Error(t, err, "a certificate for %q logged in", principal)
	}
	client, err := dial(t, addr, cur, userCert(t, ca, here))
	require.NoError(t, err, "the certificate for this server and account")
	_ = client.Close()
}

func TestServerDeniesNoRules(t *testing.T) {
	is := assert.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	// No principals rules exist for this (likely nonexistent) username.
	_, err := dial(t, addr, "nobody-nokku-test", userCert(t, ca, testPrincipal))
	is.Error(err, "expected auth to fail with no access rules")
}

func TestServerDeniesPlainKey(t *testing.T) {
	is := assert.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err, "generate key")
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err, "signer")
	_, err = dial(t, addr, currentUser(t), ssh.PublicKeys(signer))
	is.Error(err, "expected auth to reject a non-certificate key")
}

func currentUser(t *testing.T) string {
	t.Helper()
	cur, err := user.Current()
	require.NoError(t, err, "current user")
	return cur.Username
}

// If the host key changed, every known_hosts entry would break on daemon restart.
func TestHostKeysStable(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())

	s1, c1, err := loadHostKey()
	must.NoError(err, "load host key")
	defer c1.Close()
	first := s1.PublicKey().Marshal()

	s2, c2, err := loadHostKey()
	must.NoError(err, "reload host key")
	defer c2.Close()
	second := s2.PublicKey().Marshal()
	is.Equal(first, second)
}

func TestHostKeysDropStaleCert(t *testing.T) {
	must := require.New(t)
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())

	// Seed a public key for a different identity plus a certificate for it.
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	must.NoError(err, "generate other key")
	sshPub, err := ssh.NewPublicKey(otherPub)
	must.NoError(err, "encode other key")
	must.NoError(os.WriteFile(
		paths.HostKeyPub(), ssh.MarshalAuthorizedKey(sshPub), 0o644,
	), "write stale public key")
	must.NoError(os.WriteFile(paths.HostKeyCert(), []byte("stale"), 0o644), "write stale cert")

	_, closer, err := loadHostKey()
	must.NoError(err, "load host key")
	defer closer.Close()

	_, err = os.Stat(paths.HostKeyCert())
	must.ErrorIs(err, os.ErrNotExist, "certificate for a previous identity must be dropped")
}

func TestNewWithoutTrustedCA(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
	srv, err := New(Options{
		Principals: func(string) []string {
			return nil
		},
	})
	must.NoError(err, "expected server to start without a trusted CA")
	is.Empty(srv.trustedCAs)
}

func TestServerLivePrincipals(t *testing.T) {
	must := require.New(t)
	ca := newTestCA(t)
	cur, err := user.Current()
	require.NoError(t, err, "current user")

	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
	cache := state.NewCache()
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
	srv, err := New(Options{
		Principals: func(username string) []string {
			return cache.CertPrincipals(username)
		},
	})
	must.NoError(err, "new server")
	srv.SetTrust(string(ssh.MarshalAuthorizedKey(ca.pub)), nil)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	must.NoError(err, "listen")
	go srv.Serve(t.Context(), l)
	defer l.Close()

	_, err = dial(t, l.Addr().String(), cur.Username, userCert(t, ca, testPrincipal))
	must.Error(err, "expected auth to fail before the principal is granted")

	cache.Replace(map[string][]string{cur.Username: {testPrincipal}}, nil, "", nil, 0)
	client, err := dial(t, l.Addr().String(), cur.Username, userCert(t, ca, testPrincipal))
	must.NoError(err, "dial after cache update")
	defer client.Close()

	sess, err := client.NewSession()
	must.NoError(err, "new session")
	defer sess.Close()
	_, err = sess.Output("printf live")
	must.NoError(err, "exec")
}

// A partial config must not silently turn recording off.
func TestPolicyFrom(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	is.Equal(DefaultPolicy, PolicyFrom(nil))
	is.Equal(DefaultPolicy, PolicyFrom(&nokkuv1.DaemonConfig{}))

	got := PolicyFrom(&nokkuv1.DaemonConfig{RecordSessions: new(false), GatewayPorts: new(true)})
	is.False(got.Record)
	is.True(got.GatewayPorts)
	is.True(got.AllowForwarding, "unset field lost its default")
}

// relayed is a connection with the remote address a relay reports for it.
type relayed struct {
	net.Conn

	remote net.Addr
}

func (c relayed) RemoteAddr() net.Addr { return c.remote }

func TestServeConnReportsRelayedClient(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	var srv *Server
	_, closeFn := startTestServerOpts(t, ca, Options{}, func(s *Server) {
		srv = s
		// No pre-auth slot at all: only a relayed connection gets through.
		s.startups = make(chan struct{})
		s.localStartups = make(chan struct{})
	})
	defer closeFn()

	office := userCertOpts(t, ca, func(c *ssh.Certificate) {
		c.CriticalOptions = map[string]string{"source-address": "203.0.113.0/24"}
	}, testPrincipal)
	// A TCP pair, net.Pipe has no buffer and both ssh ends write first.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	must.NoError(err)
	defer l.Close()
	connect := func(from string) (*ssh.Client, error) {
		client, dialErr := net.Dial("tcp", l.Addr().String())
		must.NoError(dialErr)
		sshd, acceptErr := l.Accept()
		must.NoError(acceptErr)
		go srv.ServeConn(relayed{Conn: sshd, remote: &net.TCPAddr{IP: net.ParseIP(from)}})
		conn, chans, reqs, sshErr := ssh.NewClientConn(client, "relay", &ssh.ClientConfig{
			User:            currentUser(t),
			Auth:            []ssh.AuthMethod{office},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), // #nosec G106 - test server
			Timeout:         10 * time.Second,
		})
		if sshErr != nil {
			_ = client.Close()
			return nil, sshErr
		}
		return ssh.NewClient(conn, chans, reqs), nil
	}

	_, err = connect("198.51.100.1")
	must.Error(err, "a certificate bound to another network logged in through the relay")

	client, err := connect("203.0.113.7")
	must.NoError(err, "relayed login from the allowed network")
	defer client.Close()
	sess, err := client.NewSession()
	must.NoError(err)
	defer sess.Close()
	out, err := sess.Output("echo $SSH_CLIENT")
	must.NoError(err)
	is.True(strings.HasPrefix(string(out), "203.0.113.7 0 "), "SSH_CLIENT = %q, want the relayed address", out)
}
