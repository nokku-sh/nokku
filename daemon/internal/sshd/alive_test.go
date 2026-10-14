package sshd

import (
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
)

func TestServerMaxConnections(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{}, func(s *Server) { s.conns = make(chan struct{}, 1) })
	defer closeFn()

	auth := userCert(t, ca, testPrincipal)
	user := currentUser(t)

	c1, err := dial(t, addr, user, auth)
	must.NoError(err, "first connection")
	defer c1.Close()

	_, err = dial(t, addr, user, auth)
	must.Error(err, "second connection unexpectedly accepted")

	// Closing the first frees a slot (server notices asynchronously).
	c1.Close()
	is.Eventually(func() bool {
		c2, derr := dial(t, addr, user, auth)
		if derr == nil {
			c2.Close()
			return true
		}
		return false
	}, 5*time.Second, 20*time.Millisecond, "connection cap never released")
}

func TestServerMaxStartups(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{}, func(s *Server) { s.localStartups = make(chan struct{}, 1) })
	defer closeFn()

	// A raw TCP connection that never completes the handshake holds the single pre-auth slot.
	nc, err := net.Dial("tcp", addr)
	must.NoError(err)
	defer nc.Close()
	// Give the server time to accept and take the slot.
	time.Sleep(100 * time.Millisecond)

	_, err = dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.Error(err, "dial succeeded while the pre-auth slot was held")

	nc.Close()
	is.Eventually(func() bool {
		c, derr := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
		if derr == nil {
			c.Close()
			return true
		}
		return false
	}, 5*time.Second, 20*time.Millisecond, "pre-auth slot never released")
}

// The slot only bounds half-open peers, an authenticated idle connection must not hold one.
func TestServerMaxStartupsReleasedAfterHandshake(t *testing.T) {
	must := require.New(t)
	ca := newTestCA(t)
	slots := make(chan struct{}, 1)
	addr, closeFn := startTestServerOpts(t, ca, Options{}, func(s *Server) { s.localStartups = slots })
	defer closeFn()

	auth := userCert(t, ca, testPrincipal)
	user := currentUser(t)

	first, err := dial(t, addr, user, auth)
	must.NoError(err, "first connection")
	defer first.Close()
	// The client sees auth success before the server goroutine releases the slot.
	must.Eventually(func() bool { return len(slots) == 0 }, 5*time.Second, 5*time.Millisecond, "slot never released")

	second, err := dial(t, addr, user, auth)
	must.NoError(err, "second connection while the first was authenticated and idle")
	_ = second.Close()
}

func TestServerMaxChannels(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{}, func(s *Server) { s.maxChannels = 2 })
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	s1, err := client.NewSession()
	must.NoError(err, "session 1")
	defer s1.Close()
	s2, err := client.NewSession()
	must.NoError(err, "session 2")
	defer s2.Close()

	_, err = client.NewSession()
	must.ErrorContains(err, "too many channels")

	// Closing a session frees its slot (the server notices asynchronously).
	must.NoError(s1.Close(), "close s1")
	var s3 *ssh.Session
	is.Eventually(func() bool {
		s3, err = client.NewSession()
		return err == nil
	}, 5*time.Second, 20*time.Millisecond)
	must.NoError(err, "channel slot after close")
	defer s3.Close()
}

func TestServerClientAlive(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(
		t,
		ca,
		Options{},
		func(s *Server) { s.aliveInterval = 100 * time.Millisecond },
	)
	defer closeFn()

	// A responsive client sends a global request now and then, so the server sees inbound traffic.
	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err)
	defer client.Close()

	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
				_, _, _ = client.SendRequest("keepalive@openssh.com", true, nil)
			}
		}
	}()
	time.Sleep(700 * time.Millisecond)
	close(stop)

	sess, err := client.NewSession()
	must.NoError(err, "session after keepalives")
	defer sess.Close()
	out, err := sess.Output("echo alive")
	must.NoError(err)
	is.Equal("alive\n", string(out))
}

func TestServerClientAliveSilent(t *testing.T) {
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(
		t,
		ca,
		Options{},
		func(s *Server) { s.aliveInterval = 100 * time.Millisecond },
	)
	defer closeFn()

	// The handshake completes but global requests are never serviced, so the keepalives go unanswered.
	nc, err := net.Dial("tcp", addr)
	must.NoError(err)
	defer nc.Close()

	cfg := &ssh.ClientConfig{
		User:            currentUser(t),
		Auth:            []ssh.AuthMethod{userCert(t, ca, testPrincipal)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // #nosec G106 - test server
		Timeout:         10 * time.Second,
	}
	conn, _, _, err := ssh.NewClientConn(nc, "tcp", cfg)
	must.NoError(err)

	done := make(chan error, 1)
	go func() { done <- conn.Wait() }()
	select {
	case err = <-done:
		t.Logf("connection closed by server: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("server did not disconnect silent client")
	}
}

func TestServerBackgroundProcessReleasesConnection(t *testing.T) {
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{}, func(s *Server) { s.conns = make(chan struct{}, 1) })
	defer closeFn()

	auth := userCert(t, ca, testPrincipal)
	user := currentUser(t)

	c1, err := dial(t, addr, user, auth)
	must.NoError(err, "first connection")
	sess, err := c1.NewSession()
	must.NoError(err, "new session")
	must.NoError(sess.Start("sleep 15 &"), "start")
	// Let the shell exit, only the background sleep is left.
	time.Sleep(300 * time.Millisecond)
	c1.Close()

	assert.Eventually(t, func() bool {
		c2, derr := dial(t, addr, user, auth)
		if derr == nil {
			c2.Close()
			return true
		}
		return false
	}, 8*time.Second, 50*time.Millisecond, "background process kept the connection slot")
}

// The process ignores SIGHUP, like a job an interactive shell put in the background.
func TestServerBackgroundProcessOnPTYReleasesConnection(t *testing.T) {
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{}, func(s *Server) { s.conns = make(chan struct{}, 1) })
	defer closeFn()

	auth := userCert(t, ca, testPrincipal)
	user := currentUser(t)

	c1, err := dial(t, addr, user, auth)
	must.NoError(err, "first connection")
	sess, err := c1.NewSession()
	must.NoError(err, "new session")
	must.NoError(sess.RequestPty("xterm", 80, 24, ssh.TerminalModes{}), "request pty")
	must.NoError(sess.Start(`(trap "" HUP; exec sleep 15) &`), "start")
	// Let the shell exit, only the background sleep is left.
	time.Sleep(300 * time.Millisecond)
	c1.Close()

	assert.Eventually(t, func() bool {
		c2, derr := dial(t, addr, user, auth)
		if derr == nil {
			c2.Close()
			return true
		}
		return false
	}, 8*time.Second, 50*time.Millisecond, "background process on the pty kept the connection slot")
}

func TestStartupSlotsPerSource(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
	s, err := New(Options{Principals: func(string) []string { return nil }})
	must.NoError(err)

	addr := func(ip string) net.Addr { return net.TCPAddrFromAddrPort(netip.MustParseAddrPort(ip)) }

	var releases []func()
	for range maxSourceStartups {
		release, ok := s.acquireStartup(addr("203.0.113.7:1000"))
		must.True(ok, "slot within the per-source cap")
		releases = append(releases, release)
	}
	_, ok := s.acquireStartup(addr("203.0.113.7:1001"))
	is.False(ok, "one address took more than its share")

	_, ok = s.acquireStartup(addr("198.51.100.1:1000"))
	is.True(ok, "another address was refused")

	for range maxSourceStartups {
		_, ok = s.acquireStartup(addr("[2001:db8::1]:1000"))
		must.True(ok)
	}
	_, ok = s.acquireStartup(addr("[2001:db8::ffff]:1000"))
	is.False(ok, "addresses in one /64 must share a cap")

	// Remote slots are now exhausted (3 + 1 + 3 of 10 used, fill the rest).
	for i := range 3 {
		_, ok = s.acquireStartup(addr(fmt.Sprintf("192.0.2.%d:1000", i+1)))
		must.True(ok)
	}
	_, ok = s.acquireStartup(addr("192.0.2.200:1000"))
	is.False(ok, "remote budget is full")
	_, ok = s.acquireStartup(addr("127.0.0.1:1000"))
	is.True(ok, "loopback must not depend on the remote budget")

	releases[0]()
	_, ok = s.acquireStartup(addr("203.0.113.7:1002"))
	is.True(ok, "a released slot was not reusable")
}

func TestDropRevoked(t *testing.T) {
	must := require.New(t)
	ca := newTestCA(t)
	var srv *Server
	var revoked atomic.Bool
	addr, closeFn := startTestServerOpts(t, ca, Options{}, func(s *Server) {
		srv = s
		allowed := s.principals
		s.principals = func(username string) []string {
			if revoked.Load() {
				return nil
			}
			return allowed(username)
		}
	})
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err)
	defer client.Close()
	gone := make(chan struct{})
	go func() {
		_ = client.Wait()
		close(gone)
	}()

	// A sync that changes nothing for this user leaves the connection alone.
	srv.DropRevoked()
	select {
	case <-gone:
		t.Fatal("a connection that still has access was closed")
	case <-time.After(200 * time.Millisecond):
	}

	revoked.Store(true)
	srv.DropRevoked()
	select {
	case <-gone:
	case <-time.After(5 * time.Second):
		t.Fatal("the revoked user's connection stayed open")
	}
}

// The sync's DropRevoked cannot see a connection that is still in its handshake.
func TestRevokeDuringHandshake(t *testing.T) {
	must := require.New(t)
	ca := newTestCA(t)
	var revoked atomic.Bool
	addr, closeFn := startTestServerOpts(t, ca, Options{}, func(s *Server) {
		allowed := s.principals
		s.principals = func(username string) []string {
			if revoked.Load() {
				return nil
			}
			return allowed(username)
		}
		// The account lookup runs after the principal check, so this revoke lands mid-handshake.
		lookup := s.lookupAccount
		s.lookupAccount = func(name string) (*account, error) {
			revoked.Store(true)
			s.DropRevoked()
			return lookup(name)
		}
	})
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err)
	defer client.Close()
	gone := make(chan struct{})
	go func() {
		_ = client.Wait()
		close(gone)
	}()
	select {
	case <-gone:
	case <-time.After(5 * time.Second):
		t.Fatal("a login revoked during its handshake stayed open")
	}
}

func TestDropRevokedCA(t *testing.T) {
	must := require.New(t)
	ca := newTestCA(t)
	var srv *Server
	addr, closeFn := startTestServerOpts(t, ca, Options{}, func(s *Server) { srv = s })
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err)
	defer client.Close()
	gone := make(chan struct{})
	go func() {
		_ = client.Wait()
		close(gone)
	}()

	// A rollover that keeps the old key trusted leaves the connection alone.
	next := string(ssh.MarshalAuthorizedKey(newTestCA(t).pub))
	srv.SetTrust(next, []*nokkuv1.RetiredCAKey{{
		PublicKey:    new(string(ssh.MarshalAuthorizedKey(ca.pub))),
		TrustedUntil: timestamppb.New(time.Now().Add(time.Hour)),
	}})
	srv.DropRevoked()
	select {
	case <-gone:
		t.Fatal("a connection signed by a still trusted CA was closed")
	case <-time.After(200 * time.Millisecond):
	}

	srv.SetTrust(next, nil)
	srv.DropRevoked()
	select {
	case <-gone:
	case <-time.After(5 * time.Second):
		t.Fatal("a connection signed by a revoked CA stayed open")
	}
}
