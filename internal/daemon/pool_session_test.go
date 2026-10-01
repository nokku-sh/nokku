package daemon

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/sshclient/sshtest"
)

// bridgeToServer plays the daemon's DaemonRelay handler for one relay: it
// pumps bytes between the relay channels and a TCP connection to the test
// SSH server, including closing the relay when the server side dies, like
// handler.go does for the gRPC stream.
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

// testConn returns the registered connection for d1.
func testConn(t *testing.T, p *Pool) *daemonConn {
	t.Helper()
	p.mu.RLock()
	defer p.mu.RUnlock()
	c := p.byID["d1"]
	if c == nil {
		t.Fatal("daemon d1 is not registered")
	}
	return c
}

// slotsHeld counts the index entries with the sessions, so a leak there
// fails the same checks.
func slotsHeld(t *testing.T, p *Pool) (sessions, slots int) {
	t.Helper()
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.sessions) + len(p.owned), len(p.relayCounts)
}

// serveRelayRequests registers every RelayOpen StartSession sends, as the
// daemon's control stream would, and bridges the relay to the test server.
// It runs until the test ends.
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
			CA:            srv.CA(t),
			HostPrincipal: srv.HostPrincipal,
		})
		res <- result{s, err}
	}()

	deadline := time.After(3 * time.Second)
	for {
		select {
		case r := <-res:
			if r.err != nil {
				t.Fatalf("StartSession: %v", r.err)
			}
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

// TestPool_StartSession_EndsWithContext: the session belongs to its caller,
// so the caller's ctx ending must tear it down without an explicit Close.
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
		CA:            srv.CA(t),
		HostPrincipal: srv.HostPrincipal,
	})
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	if got := len(p.ListSessions("d1")); got != 1 {
		t.Fatalf("ListSessions(d1) = %d, want 1", got)
	}

	cancel()
	waitStdoutClosed(t, s, "the caller's ctx ended")
	deadline := time.After(2 * time.Second)
	for {
		sessions, slots := slotsHeld(t, p)
		if sessions == 0 && slots == 0 {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("leak after ctx end: %d sessions, %d slots held", sessions, slots)
		default:
		}
		time.Sleep(time.Millisecond)
	}
}

// TestPool_StartSession walks a full web session over a real in-process SSH
// server: env and pty reach sshd through the relay, stdin echoes back on
// Stdout, resizes arrive, and CloseSession tears everything down.
func TestPool_StartSession(t *testing.T) {
	p := newTestPool(t)
	p.registerDaemon(t.Context(), "d1", "w1")
	srv := sshtest.NewServer(t)

	s := startTestSession(t, p, srv, "web-1")

	deadline := time.After(2 * time.Second)
	for srv.Env("NOKKU_SESSION_ID") != "web-1" {
		select {
		case <-deadline:
			t.Fatalf("session env never arrived, got %q", srv.Env("NOKKU_SESSION_ID"))
		default:
		}
		time.Sleep(time.Millisecond)
	}
	if _, cols, rows := srv.Pty(); cols != 80 || rows != 24 {
		t.Errorf("pty size = %dx%d, want 80x24", cols, rows)
	}

	// Stdin goes to the shell and the echo comes out on Stdout.
	if err := s.Write([]byte("ping\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
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

	if err := s.Resize(100, 40); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	deadline = time.After(2 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("window change never reached the server")
		default:
		}
		if changes := srv.WindowChanges(); len(changes) > 0 {
			if changes[0].Cols != 100 || changes[0].Rows != 40 {
				t.Errorf("window change = %+v, want 100x40", changes[0])
			}
			break
		}
		time.Sleep(time.Millisecond)
	}

	// CloseSession must end the session, clean the map, and free the relay
	// slot.
	p.CloseSession("web-1")
	waitStdoutClosed(t, s, "CloseSession")
	deadline = time.After(2 * time.Second)
	for {
		sessions, slots := slotsHeld(t, p)
		if sessions == 0 && slots == 0 {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("leak after CloseSession: %d sessions, %d slots held", sessions, slots)
		default:
		}
		time.Sleep(time.Millisecond)
	}
}

// TestPool_StartSession_RejectsInactiveCA: a deactivated (or missing) CA must
// not mint web-session certificates, whatever the rest of the config says.
func TestPool_StartSession_RejectsInactiveCA(t *testing.T) {
	p := newTestPool(t)
	cases := map[string]*db.CertificateAuthority{
		"missing":  nil,
		"inactive": {},
	}
	for name, ca := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := p.StartSession(t.Context(), SessionConfig{
				DaemonID:  "d1",
				SessionID: "s1",
				UserID:    "u1",
				Username:  "root",
				CA:        ca,
			})
			if !errors.Is(err, ErrCAInactive) {
				t.Fatalf("StartSession err = %v, want ErrCAInactive", err)
			}
		})
	}
}

// TestPool_StartSession_HandshakeFailure: a CA the server does not trust
// fails the dial, the error surfaces to the caller, and no slot or session
// is left behind.
func TestPool_StartSession_HandshakeFailure(t *testing.T) {
	p := newTestPool(t)
	p.registerDaemon(t.Context(), "d1", "w1")
	srv := sshtest.NewServer(t)

	c := testConn(t, p)
	go serveRelayRequests(t, p, c, srv.Addr())

	errCh := make(chan error, 1)
	go func() {
		_, err := p.StartSession(t.Context(), SessionConfig{
			DaemonID:      "d1",
			SessionID:     "web-2",
			Username:      "user",
			UserID:        "u1",
			CA:            sshtest.NewCA(t),
			HostPrincipal: srv.HostPrincipal,
		})
		errCh <- err
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("StartSession must fail against a rogue CA")
		}
		if !strings.Contains(err.Error(), "ssh session") {
			t.Errorf("error should wrap the ssh dial, got %v", err)
		}
		deadline := time.After(2 * time.Second)
		for {
			sessions, slots := slotsHeld(t, p)
			if sessions == 0 && slots == 0 {
				return
			}
			select {
			case <-deadline:
				t.Fatalf("leak after failed dial: %d sessions, %d slots held", sessions, slots)
			default:
			}
			time.Sleep(time.Millisecond)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("StartSession did not fail in time")
	}
}

// TestPool_StartSession_ServerDeath: the sshd side dying mid-session must
// close Stdout, and the owner's Close then releases the slot.
func TestPool_StartSession_ServerDeath(t *testing.T) {
	p := newTestPool(t)
	p.registerDaemon(t.Context(), "d1", "w1")
	srv := sshtest.NewServer(t)

	s := startTestSession(t, p, srv, "web-3")
	srv.Close()

	waitStdoutClosed(t, s, "the ssh server died")
	s.Close()
	deadline := time.After(2 * time.Second)
	for {
		sessions, slots := slotsHeld(t, p)
		if sessions == 0 && slots == 0 {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("leak after server death: %d sessions, %d slots held", sessions, slots)
		default:
		}
		time.Sleep(time.Millisecond)
	}
}
