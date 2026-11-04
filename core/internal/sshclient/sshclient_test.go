package sshclient

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/sshclient/sshtest"
)

func testConfig(t *testing.T, srv *sshtest.Server) Config {
	t.Helper()
	return Config{
		HostPrincipal: srv.HostPrincipal,
		Username:      "user",
		Signer:        srv.UserSigner(t, srv.UserPrincipal, "user"),
		HostCA:        srv.HostCAKey(),
	}
}

func dialForTest(t *testing.T, srv *sshtest.Server, cfg Config) *Terminal {
	t.Helper()
	conn, err := net.Dial("tcp", srv.Addr())
	require.NoError(t, err, "dial test server")
	term, err := DialTerminal(t.Context(), conn, cfg)
	if err != nil {
		_ = conn.Close()
	}
	require.NoError(t, err, "DialTerminal")
	return term
}

func waitForShell(t *testing.T, srv *sshtest.Server) {
	t.Helper()
	require.Eventually(t, srv.ShellStarted, 2*time.Second, time.Millisecond, "shell request never reached the server")
}

// The full dial: host check against the CA, pty size, echo and window-change.
func TestDialTerminal_HappyPath(t *testing.T) {
	srv := sshtest.NewServer(t)
	term := dialForTest(t, srv, testConfig(t, srv))
	defer term.Close()

	waitForShell(t, srv)

	assert.Equal(t, "user", srv.ConnUser())
	_, cols, rows := srv.Pty()
	assert.EqualValues(t, 80, cols)
	assert.EqualValues(t, 24, rows)

	_, err := term.Write([]byte("ping\n"))
	require.NoError(t, err)

	deadline := time.After(2 * time.Second)
	var got []byte
collect:
	for {
		select {
		case chunk, ok := <-term.Stdout():
			require.True(t, ok, "stdout closed before echo arrived")
			got = append(got, chunk...)
			if strings.Contains(string(got), "ping") {
				break collect
			}
		case <-deadline:
			t.Fatalf("no echo, got %q", got)
		}
	}

	require.NoError(t, term.Resize(100, 40))
	require.Eventually(t, func() bool { return len(srv.WindowChanges()) > 0 },
		2*time.Second, time.Millisecond, "window change never reached the server")
	change := srv.WindowChanges()[0]
	assert.EqualValues(t, 100, change.Cols)
	assert.EqualValues(t, 40, change.Rows)
}

// A host certificate signed by any other CA must fail the handshake.
func TestDialTerminal_WrongCA(t *testing.T) {
	srv := sshtest.NewServer(t)
	rogue := sshtest.NewServer(t)

	cfg := testConfig(t, srv)
	cfg.HostCA = rogue.HostCAKey()

	conn, err := net.Dial("tcp", srv.Addr())
	require.NoError(t, err, "dial test server")
	defer func() { _ = conn.Close() }()
	_, err = DialTerminal(t.Context(), conn, cfg)
	require.Error(t, err, "handshake with a rogue CA must fail")
}

// The server rejects an unknown certificate, and the dial fails, not hangs.
func TestDialTerminal_BadUserCert(t *testing.T) {
	srv := sshtest.NewServer(t)
	cfg := testConfig(t, srv)
	cfg.Signer = srv.UserSigner(t, "someone-else", "user")

	conn, err := net.Dial("tcp", srv.Addr())
	require.NoError(t, err, "dial test server")
	defer func() { _ = conn.Close() }()
	_, err = DialTerminal(t.Context(), conn, cfg)
	require.Error(t, err, "handshake with an unauthorized principal must fail")
}

// A server that never speaks SSH must not hang the caller past its deadline.
func TestDialTerminal_CtxCancel(t *testing.T) {
	stall, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = stall.Close() }()
	go func() {
		for {
			c, err := stall.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()

	conn, err := net.Dial("tcp", stall.Addr().String())
	require.NoError(t, err, "dial stall server")
	defer func() { _ = conn.Close() }()

	srv := sshtest.NewServer(t)
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	cfg := testConfig(t, srv)
	dialed := make(chan error, 1)
	go func() {
		_, err := DialTerminal(ctx, conn, cfg)
		dialed <- err
	}()
	select {
	case err := <-dialed:
		require.Error(t, err, "dial must fail when the context expires")
	case <-time.After(5 * time.Second):
		t.Fatal("dial ignored its context")
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
		assert.False(t, ok, "stdout should be closed after Close")
	case <-time.After(2 * time.Second):
		t.Fatal("stdout not closed after Close")
	}
}

// Ctrl+D ends the remote shell, the only ending that closes the web tab.
func TestTerminal_ShellExit(t *testing.T) {
	srv := sshtest.NewServer(t)
	term := dialForTest(t, srv, testConfig(t, srv))
	defer term.Close()
	waitForShell(t, srv)

	_, err := term.Write([]byte{0x04})
	require.NoError(t, err)
	deadline := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-term.Stdout():
			if ok {
				continue
			}
			assert.True(t, term.Exited(), "Exited should be true after the shell reported its exit status")
			return
		case <-deadline:
			t.Fatal("stdout not closed after the shell exited")
		}
	}
}

// A dropped connection closes Stdout, that is how the pool sees a dead relay.
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
				assert.False(t, term.Exited(), "a dropped connection is not a shell exit")
				return
			}
		case <-deadline:
			t.Fatal("stdout not closed after the server dropped the connection")
		}
	}
}
