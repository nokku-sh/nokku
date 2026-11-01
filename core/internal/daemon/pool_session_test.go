package daemon

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokku/core/internal/sshclient/sshtest"
)

// A browser terminal is a login: the CA's source list, no forced command.
func TestSessionCertificateLimits(t *testing.T) {
	ca, signer := sshtest.NewCA(t)
	ca.SourceAddress = "10.0.0.0/8"

	session, err := mintSessionCert(ca, signer, "user@target:root", "session")
	require.NoError(t, err)
	cert, ok := session.PublicKey().(*ssh.Certificate)
	require.True(t, ok, "the session signer holds a %T", session.PublicKey())
	assert.Equal(t, map[string]string{"source-address": "10.0.0.0/8"}, cert.CriticalOptions)
}

// bridgeToServer plays the daemon's DaemonRelay handler for one relay.
func bridgeToServer(relay *Relay, addr string) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		relay.close()
		return
	}
	go func() {
		defer func() { _ = conn.Close() }()
		for {
			select {
			case data := <-relay.toDaemon:
				if _, err := conn.Write(data); err != nil {
					relay.close()
					return
				}
			case <-relay.done():
				return
			}
		}
	}()
	go func() {
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				select {
				case relay.toUser <- chunk:
				case <-relay.done():
					return
				}
			}
			if err != nil {
				relay.close()
				return
			}
		}
	}()
}

func testConn(t *testing.T, p *Pool) *daemonConn {
	t.Helper()
	p.mu.RLock()
	defer p.mu.RUnlock()
	c := p.byID["d1"]
	require.NotNil(t, c, "daemon d1 is not registered")
	return c
}

// waitNothingHeld counts the index entries too, so a leak there fails here.
func waitNothingHeld(t *testing.T, p *Pool, after string) {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		p.mu.RLock()
		defer p.mu.RUnlock()
		assert.Zero(c, len(p.sessions)+len(p.owned), "sessions held")
		assert.Empty(c, p.relayCounts, "slots held")
	}, 2*time.Second, time.Millisecond, "leak after %s", after)
}

// serveRelayRequests registers every RelayOpen as the control stream would.
func serveRelayRequests(t *testing.T, p *Pool, c *daemonConn, addr string) {
	t.Helper()
	for {
		select {
		case msg := <-c.send:
			if id := msg.GetRelayOpen().GetRelayId(); id != "" {
				if relay := p.registerRelay(id, "d1"); relay != nil {
					bridgeToServer(relay, addr)
				}
			}
		case <-t.Context().Done():
			return
		}
	}
}

func startTestSession(t *testing.T, p *Pool, srv *sshtest.Server, sessionID string) *Session {
	t.Helper()
	c := testConn(t, p)
	go serveRelayRequests(t, p, c, srv.Addr())

	type result struct {
		s   *Session
		err error
	}
	res := make(chan result, 1)
	go func() {
		s, err := p.StartSession(t.Context(), SessionConfig{
			DaemonID:      "d1",
			SessionID:     sessionID,
			Username:      "user",
			UserID:        "u1",
			CA:            srv.CA(),
			CASigner:      srv.CASigner(),
			HostPrincipal: srv.HostPrincipal,
		})
		res <- result{s, err}
	}()

	deadline := time.After(3 * time.Second)
	for {
		select {
		case r := <-res:
			require.NoError(t, r.err, "StartSession")
			return r.s
		case <-deadline:
			t.Fatal("StartSession never completed")
		}
	}
}

func waitStdoutClosed(t *testing.T, s *Session, after string) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-s.Stdout():
			if !ok {
				return
			}
		case <-deadline:
			t.Fatalf("Stdout not closed after %s", after)
		}
	}
}

// The caller owns the session, so its ctx ending tears it down without Close.
func TestPool_StartSession_EndsWithContext(t *testing.T) {
	p := newTestPool(t)
	p.registerDaemon(t.Context(), "d1", "w1")
	srv := sshtest.NewServer(t)
	c := testConn(t, p)
	go serveRelayRequests(t, p, c, srv.Addr())

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	s, err := p.StartSession(ctx, SessionConfig{
		DaemonID:      "d1",
		SessionID:     "web-ctx",
		Username:      "user",
		UserID:        "u1",
		CA:            srv.CA(),
		CASigner:      srv.CASigner(),
		HostPrincipal: srv.HostPrincipal,
	})
	require.NoError(t, err, "StartSession")
	require.Len(t, p.ListSessions("d1"), 1)

	cancel()
	waitStdoutClosed(t, s, "the caller's ctx ended")
	waitNothingHeld(t, p, "ctx end")
}

// A full web session over a real SSH server: cert, pty, echo, resize, Close.
func TestPool_StartSession(t *testing.T) {
	p := newTestPool(t)
	p.registerDaemon(t.Context(), "d1", "w1")
	srv := sshtest.NewServer(t)

	s := startTestSession(t, p, srv, "web-1")

	require.Eventually(t, srv.ShellStarted, 2*time.Second, time.Millisecond, "shell request never arrived")
	assert.Equal(t, "nokku:web:session:web-1", srv.KeyID(), "the daemon reads the recording id from the key id")
	_, cols, rows := srv.Pty()
	assert.EqualValues(t, 80, cols)
	assert.EqualValues(t, 24, rows)

	require.NoError(t, s.Write([]byte("ping\n")))
	var got []byte
collect:
	for {
		select {
		case chunk := <-s.Stdout():
			got = append(got, chunk...)
			if strings.Contains(string(got), "ping") {
				break collect
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("no echo on Stdout, got %q", got)
		}
	}

	require.NoError(t, s.Resize(100, 40))
	require.Eventually(t, func() bool { return len(srv.WindowChanges()) > 0 },
		2*time.Second, time.Millisecond, "window change never reached the server")
	change := srv.WindowChanges()[0]
	assert.EqualValues(t, 100, change.Cols)
	assert.EqualValues(t, 40, change.Rows)

	s.Close()
	waitStdoutClosed(t, s, "Close")
	waitNothingHeld(t, p, "Close")
}

// An untrusted CA fails the dial, and no slot or session is left behind.
func TestPool_StartSession_HandshakeFailure(t *testing.T) {
	p := newTestPool(t)
	p.registerDaemon(t.Context(), "d1", "w1")
	srv := sshtest.NewServer(t)

	c := testConn(t, p)
	go serveRelayRequests(t, p, c, srv.Addr())

	rogue, rogueSigner := sshtest.NewCA(t)
	errCh := make(chan error, 1)
	go func() {
		_, err := p.StartSession(t.Context(), SessionConfig{
			DaemonID:      "d1",
			SessionID:     "web-2",
			Username:      "user",
			UserID:        "u1",
			CA:            rogue,
			CASigner:      rogueSigner,
			HostPrincipal: srv.HostPrincipal,
		})
		errCh <- err
	}()

	var err error
	select {
	case err = <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("StartSession did not fail in time")
	}
	require.Error(t, err, "StartSession must fail against a rogue CA")
	waitNothingHeld(t, p, "failed dial")
	assert.ErrorContains(t, err, "ssh session", "error should wrap the ssh dial")
}

// sshd dying mid-session closes Stdout, and the owner's Close frees the slot.
func TestPool_StartSession_ServerDeath(t *testing.T) {
	p := newTestPool(t)
	p.registerDaemon(t.Context(), "d1", "w1")
	srv := sshtest.NewServer(t)

	s := startTestSession(t, p, srv, "web-3")
	srv.Close()

	waitStdoutClosed(t, s, "the ssh server died")
	s.Close()
	waitNothingHeld(t, p, "server death")
}
