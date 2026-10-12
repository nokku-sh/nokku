package sshclient

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nokku-sh/nokku/internal/sshclient/sshtest"
)

func testConfig(t *testing.T, srv *sshtest.Server) Config {
	t.Helper()
	return Config{
		HostPrincipal: srv.HostPrincipal,
		Username:      "user",
		Signer:        srv.UserSigner(t, srv.UserPrincipal, "user"),
		CAKey:         srv.CAKey(),
	}
}

func dialForTest(t *testing.T, srv *sshtest.Server, cfg Config) *Terminal {
	t.Helper()
	conn, err := net.Dial("tcp", srv.Addr())
	if err != nil {
		t.Fatalf("dial test server: %v", err)
	}
	term, err := DialTerminal(t.Context(), conn, cfg)
	if err != nil {
		_ = conn.Close()
		t.Fatalf("DialTerminal: %v", err)
	}
	return term
}

func waitForShell(t *testing.T, srv *sshtest.Server) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if srv.ShellStarted() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("shell request never reached the server")
}

// The full dial: host verification against the CA, the pty size, echo and window-change.
func TestDialTerminal_HappyPath(t *testing.T) {
	srv := sshtest.NewServer(t)
	term := dialForTest(t, srv, testConfig(t, srv))
	defer term.Close()

	waitForShell(t, srv)

	if got := srv.ConnUser(); got != "user" {
		t.Errorf("connection user = %q, want user", got)
	}
	if _, cols, rows := srv.Pty(); cols != 80 || rows != 24 {
		t.Errorf("pty size = %dx%d, want 80x24", cols, rows)
	}

	go func() {
		time.Sleep(50 * time.Millisecond)
		if _, err := term.Write([]byte("ping\n")); err != nil {
			t.Errorf("Write: %v", err)
		}
	}()

	deadline := time.After(2 * time.Second)
	var got []byte
collect:
	for {
		select {
		case chunk, ok := <-term.Stdout():
			if !ok {
				t.Fatal("stdout closed before echo arrived")
			}
			got = append(got, chunk...)
			if strings.Contains(string(got), "ping") {
				break collect
			}
		case <-deadline:
			t.Fatalf("no echo, got %q", got)
		}
	}

	if err := term.Resize(100, 40); err != nil {
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
			return
		}
		time.Sleep(time.Millisecond)
	}
}

// The security-critical one: a host certificate signed by any other CA must fail the handshake.
func TestDialTerminal_WrongCA(t *testing.T) {
	srv := sshtest.NewServer(t)
	rogue := sshtest.NewServer(t)

	cfg := testConfig(t, srv)
	cfg.CAKey = rogue.CAKey()

	conn, err := net.Dial("tcp", srv.Addr())
	if err != nil {
		t.Fatalf("dial test server: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := DialTerminal(t.Context(), conn, cfg); err == nil {
		t.Fatal("handshake with a rogue CA must fail")
	}
}

// The server rejects certificates it does not know, and the dial fails instead of hanging.
func TestDialTerminal_BadUserCert(t *testing.T) {
	srv := sshtest.NewServer(t)
	cfg := testConfig(t, srv)
	// A cert for a principal the server does not accept.
	cfg.Signer = srv.UserSigner(t, "someone-else", "user")

	conn, err := net.Dial("tcp", srv.Addr())
	if err != nil {
		t.Fatalf("dial test server: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := DialTerminal(t.Context(), conn, cfg); err == nil {
		t.Fatal("handshake with an unauthorized principal must fail")
	}
}

// A server that accepts TCP but never speaks SSH must not hang the caller past the context deadline.
func TestDialTerminal_CtxCancel(t *testing.T) {
	stall, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = stall.Close() }()
	go func() {
		for {
			c, err := stall.Accept()
			if err != nil {
				return
			}
			// Hold the connection open silently.
			go func() {
				time.Sleep(5 * time.Second)
				_ = c.Close()
			}()
		}
	}()

	conn, err := net.Dial("tcp", stall.Addr().String())
	if err != nil {
		t.Fatalf("dial stall server: %v", err)
	}
	defer func() { _ = conn.Close() }()

	srv := sshtest.NewServer(t)
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	if _, err := DialTerminal(ctx, conn, testConfig(t, srv)); err == nil {
		t.Fatal("dial must fail when the context expires")
	}
}

// Close ends the output stream, so the session wiring can exit.
func TestTerminal_CloseTeardown(t *testing.T) {
	srv := sshtest.NewServer(t)
	term := dialForTest(t, srv, testConfig(t, srv))
	waitForShell(t, srv)

	term.Close()
	select {
	case _, ok := <-term.Stdout():
		if ok {
			t.Error("stdout should be closed after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stdout not closed after Close")
	}
}

// Ctrl+D ends the remote shell. That is the only ending the web terminal closes its tab for.
func TestTerminal_ShellExit(t *testing.T) {
	srv := sshtest.NewServer(t)
	term := dialForTest(t, srv, testConfig(t, srv))
	defer term.Close()
	waitForShell(t, srv)

	if _, err := term.Write([]byte{0x04}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	deadline := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-term.Stdout():
			if ok {
				continue
			}
			if !term.Exited() {
				t.Error("Exited should be true after the shell reported its exit status")
			}
			return
		case <-deadline:
			t.Fatal("stdout not closed after the shell exited")
		}
	}
}

// A dropped connection closes Stdout, which is how the pool wiring notices a dead relay.
func TestTerminal_TransportDeath(t *testing.T) {
	srv := sshtest.NewServer(t)
	term := dialForTest(t, srv, testConfig(t, srv))
	waitForShell(t, srv)

	srv.Close()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-term.Stdout():
			if !ok {
				if term.Exited() {
					t.Error("a dropped connection is not a shell exit")
				}
				return
			}
		case <-deadline:
			t.Fatal("stdout not closed after the server dropped the connection")
		}
	}
}
