package sshd

import (
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func idleSession(t *testing.T, idle time.Duration) *ssh.Session {
	t.Helper()
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{Policy: Policy{IdleTimeout: idle}})
	t.Cleanup(closeFn)

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	require.NoError(t, err, "dial")
	t.Cleanup(func() { _ = client.Close() })
	sess, err := client.NewSession()
	require.NoError(t, err, "new session")
	t.Cleanup(func() { _ = sess.Close() })
	return sess
}

func waitDone(sess *ssh.Session) <-chan error {
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	return done
}

func TestIdleTimeoutClosesAQuietTerminal(t *testing.T) {
	sess := idleSession(t, 300*time.Millisecond)
	require.NoError(t, sess.RequestPty("xterm", 80, 24, ssh.TerminalModes{}), "request pty")
	require.NoError(t, sess.Start("sleep 30"), "start")

	select {
	case err := <-waitDone(sess):
		require.Error(t, err, "an idle session must end with a failure, not as if the command finished")
	case <-time.After(5 * time.Second):
		t.Fatal("a terminal without input outlived the idle timeout")
	}
}

func TestIdleTimeoutLeavesCommandsWithoutTerminal(t *testing.T) {
	sess := idleSession(t, 200*time.Millisecond)

	require.NoError(t, sess.Run("sleep 1"), "a job without a terminal must run past the idle timeout")
}

func TestIdleTimeoutCountsFromTheLastKeystroke(t *testing.T) {
	sess := idleSession(t, 500*time.Millisecond)
	require.NoError(t, sess.RequestPty("xterm", 80, 24, ssh.TerminalModes{}), "request pty")
	stdin, err := sess.StdinPipe()
	require.NoError(t, err, "stdin")
	sess.Stdout = io.Discard
	require.NoError(t, sess.Start("cat"), "start")
	done := waitDone(sess)

	// Typing for three times the timeout keeps it open.
	for range 15 {
		_, err = stdin.Write([]byte("x"))
		require.NoError(t, err, "type")
		select {
		case <-done:
			t.Fatal("the session closed while someone was typing")
		case <-time.After(100 * time.Millisecond):
		}
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the session stayed open after the typing stopped")
	}
}
