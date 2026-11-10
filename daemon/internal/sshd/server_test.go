package sshd

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
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

	"github.com/nokku-sh/nokku/daemon/internal/state"
)

const testPrincipal = "9a3c2a0f-5f1e-4a7b-9c4d-2e6b8f0a1c3d"

// The core's default cert template. The daemon enforces permit-*.
var defaultExtensions = map[string]string{
	"permit-pty":              "",
	"permit-user-rc":          "",
	"permit-port-forwarding":  "",
	"permit-agent-forwarding": "",
}

type testCA struct {
	pub    ssh.PublicKey
	signer ssh.Signer
}

// relayed is a connection with the remote address a relay reports for it.
type relayed struct {
	net.Conn

	remote net.Addr
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
	return certAuth(t, ca, userSigner, opts, principals...)
}

// certAuth logs in with a certificate the CA signed for the signer's key.
func certAuth(
	t *testing.T,
	ca testCA,
	signer ssh.Signer,
	opts func(*ssh.Certificate),
	principals ...string,
) ssh.AuthMethod {
	t.Helper()
	cert := &ssh.Certificate{
		Key:             signer.PublicKey(),
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
	certSigner, err := ssh.NewCertSigner(cert, signer)
	require.NoError(t, err, "cert signer")
	return ssh.PublicKeys(certSigner)
}

// The default principals allow testPrincipal for the current user only.
func startTestServer(t *testing.T, ca testCA) (addr string, closeFn func()) {
	t.Helper()
	return startTestServerOpts(t, ca)
}

func startTestServerOpts(t *testing.T, ca testCA, tweaks ...func(*Server)) (addr string, closeFn func()) {
	t.Helper()
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
	srv, err := New(nil, nil)
	require.NoError(t, err, "new server")
	srv.SetAccess(testAccess(t, ca))
	for _, tweak := range tweaks {
		tweak(srv)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "listen")
	go srv.Serve(t.Context(), l)
	return l.Addr().String(), func() { _ = l.Close() }
}

// testAccess trusts ca and admits testPrincipal as this user, policy off.
func testAccess(t *testing.T, ca testCA) *state.Access {
	t.Helper()
	off := new(false)
	return &state.Access{
		Principals:   map[string][]string{currentUser(t): {testPrincipal}},
		UserCA:       string(ssh.MarshalAuthorizedKey(ca.pub)),
		DaemonConfig: &nokkuv1.DaemonConfig{RecordSessions: off, AllowForwarding: off, AllowAgentForwarding: off},
		SyncedAt:     time.Now(),
	}
}

func withLog(log *slog.Logger) func(*Server) {
	return func(s *Server) { s.log = log }
}

// withPolicy sets only the switches of p, a core config leaves unset ones on.
func withPolicy(p policy) func(*Server) {
	return func(s *Server) {
		a := *s.access.Load()
		a.policy = p
		s.access.Store(&a)
	}
}

func dial(t *testing.T, addr, username string, auth ssh.AuthMethod) (*ssh.Client, error) {
	t.Helper()
	cfg := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // #nosec G106
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

	// Killing its own shell gives exit-signal, the Go client maps it to 128+n.
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

func TestServerDeniesCertificateOutsideItsValidity(t *testing.T) {
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	now := uint64(time.Now().Unix())
	for name, window := range map[string][2]uint64{
		"expired":       {now - 7200, now - 3600},
		"not yet valid": {now + 3600, now + 7200},
	} {
		t.Run(name, func(t *testing.T) {
			cert := userCertOpts(t, ca, func(c *ssh.Certificate) {
				c.ValidAfter, c.ValidBefore = window[0], window[1]
			}, testPrincipal)
			_, err := dial(t, addr, currentUser(t), cert)
			require.Error(t, err, "logged in outside the window of the certificate")
		})
	}
}

func TestServerDeniesWrongPrincipal(t *testing.T) {
	is := assert.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	_, err := dial(t, addr, currentUser(t), userCert(t, ca, "unknown-principal"))
	is.Error(err, "expected auth to fail with unauthorized principal")
}

// Principals compare whole, so one for another server or account opens nothing.
func TestServerDeniesCertificateOfAnotherServerOrAccount(t *testing.T) {
	ca := newTestCA(t)
	cur := currentUser(t)
	here := "subject@this-server:" + cur
	addr, closeFn := startTestServerOpts(t, ca, func(s *Server) {
		a := testAccess(t, ca)
		a.Principals = map[string][]string{cur: {here}}
		s.SetAccess(a)
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

func TestNewWithoutTrustedCA(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
	srv, err := New(nil, nil)
	must.NoError(err, "expected server to start without a trusted CA")
	is.Empty(srv.access.Load().ca)
}

func TestServerLivePrincipals(t *testing.T) {
	must := require.New(t)
	ca := newTestCA(t)

	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
	srv, err := New(nil, nil)
	must.NoError(err, "new server")
	granted := testAccess(t, ca)
	srv.SetAccess(&state.Access{UserCA: granted.UserCA, DaemonConfig: granted.DaemonConfig, SyncedAt: granted.SyncedAt})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	must.NoError(err, "listen")
	go srv.Serve(t.Context(), l)
	defer l.Close()

	_, err = dial(t, l.Addr().String(), currentUser(t), userCert(t, ca, testPrincipal))
	must.Error(err, "expected auth to fail before the principal is granted")

	srv.SetAccess(granted)
	client, err := dial(t, l.Addr().String(), currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial after the grant synced")
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
	is.Equal(defaultPolicy, policyFrom(nil))
	is.Equal(defaultPolicy, policyFrom(&nokkuv1.DaemonConfig{}))

	got := policyFrom(&nokkuv1.DaemonConfig{RecordSessions: new(false), GatewayPorts: new(true)})
	is.False(got.Record)
	is.True(got.GatewayPorts)
	is.True(got.AllowForwarding, "unset field lost its default")
}

func (c relayed) RemoteAddr() net.Addr { return c.remote }

func TestServeConnReportsRelayedClient(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	var srv *Server
	_, closeFn := startTestServerOpts(t, ca, func(s *Server) {
		srv = s
		// No pre-auth slot at all: only a relayed connection gets through.
		s.startupsFull = 0
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
		go srv.ServeConn(t.Context(), relayed{Conn: sshd, remote: &net.TCPAddr{IP: net.ParseIP(from)}})
		conn, chans, reqs, sshErr := ssh.NewClientConn(client, "relay", &ssh.ClientConfig{
			User:            currentUser(t),
			Auth:            []ssh.AuthMethod{office},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), // #nosec G106
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

// Relayed connections hold at most half the slots, so direct logins stay open.
func TestRelayCapLeavesRoomForDirectLogins(t *testing.T) {
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
	srv, err := New(nil, nil)
	require.NoError(t, err)
	assert.Less(t, cap(srv.relayed), cap(srv.conns), "relayed connections could take every slot")

	for range cap(srv.relayed) {
		srv.relayed <- struct{}{}
	}
	server, client := net.Pipe()
	srv.ServeConn(t.Context(), server)
	_, err = client.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF, "a relayed connection past the relay cap was served")
	assert.Empty(t, srv.conns, "a refused relay kept a connection slot")
}

// A restart waits for connections past their handshake, not for a port scan.
func TestIdleCountsLoggedInConnections(t *testing.T) {
	ca := newTestCA(t)
	var srv *Server
	addr, closeFn := startTestServerOpts(t, ca, func(s *Server) { srv = s })
	defer closeFn()
	assert.True(t, srv.Idle())

	scan, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer scan.Close()
	assert.True(t, srv.Idle(), "an open socket with no login held off the restart")

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	require.NoError(t, err)
	require.Eventually(t, func() bool { return !srv.Idle() }, 2*time.Second, time.Millisecond,
		"a login did not count")
	require.NoError(t, client.Close())
	require.Eventually(t, srv.Idle, 2*time.Second, time.Millisecond, "the connection stayed counted")
}
