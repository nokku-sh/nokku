//go:build asroot

package sshd

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// A fixed id far from the usual ones, so the account never owns the files of whoever built the binary.
const (
	asUser   = "nokku-asuser"
	asUserID = 4242
)

var procIDs = regexp.MustCompile(`(Uid|Gid|Groups):[ \t]*([0-9 \t]*)`)

// Needs root, so it runs in a container: task daemon:test:root. Every way a session reaches the OS must do so as the
// user, a feature that forgets the switch runs as root.
func TestSessionsRunAsTheUser(t *testing.T) {
	require.Zero(t, os.Geteuid(), "this test needs root, run it with task daemon:test:root")
	addUser(t)
	client := dialAsUser(t)
	want := strconv.Itoa(asUserID)

	t.Run("shell", func(t *testing.T) {
		sess, err := client.NewSession()
		require.NoError(t, err)
		defer sess.Close()
		require.NoError(t, sess.RequestPty("xterm", 80, 24, ssh.TerminalModes{ssh.ECHO: 0}))
		stdin, err := sess.StdinPipe()
		require.NoError(t, err)
		stdout, err := sess.StdoutPipe()
		require.NoError(t, err)
		require.NoError(t, sess.Shell())
		const script = `grep -E '^(Uid|Gid|Groups):' /proc/$$/status; stat -c 'tty=%u' "$(tty)"; exit`
		_, err = io.WriteString(stdin, script+"\n")
		require.NoError(t, err)
		out, err := io.ReadAll(stdout)
		require.NoError(t, err)
		assertIDs(t, string(out), want)
		assert.Contains(t, string(out), "tty="+want, "the pty is not the user's")
	})

	t.Run("exec", func(t *testing.T) {
		sess, err := client.NewSession()
		require.NoError(t, err)
		defer sess.Close()
		out, err := sess.Output(`grep -E '^(Uid|Gid|Groups):' /proc/$$/status`)
		require.NoError(t, err)
		assertIDs(t, string(out), want)
	})

	t.Run("file transfer", func(t *testing.T) {
		sc, err := sftp.NewClient(client)
		require.NoError(t, err)
		defer sc.Close()
		f, err := sc.Create("/home/" + asUser + "/sent-over-sftp")
		require.NoError(t, err)
		_, err = f.Write([]byte("hello"))
		require.NoError(t, err)
		require.NoError(t, f.Close())

		info, err := os.Stat("/home/" + asUser + "/sent-over-sftp")
		require.NoError(t, err)
		st, ok := info.Sys().(*syscall.Stat_t)
		require.True(t, ok)
		assert.EqualValues(t, asUserID, st.Uid, "the file SFTP wrote is not the user's")
		assert.EqualValues(t, asUserID, st.Gid)
	})

	t.Run("direct forward", func(t *testing.T) {
		var lc net.ListenConfig
		ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer ln.Close()
		fwd, err := client.Dial("tcp", ln.Addr().String())
		require.NoError(t, err)
		defer fwd.Close()
		c, err := ln.Accept()
		require.NoError(t, err)
		defer c.Close()

		// The far end of the accepted connection is the socket the forward dialed with.
		assert.Equal(t, asUserID, socketOwner(t, addrPort(c.RemoteAddr()), addrPort(ln.Addr())),
			"the forward dialed as another user")
	})

	t.Run("remote forward", func(t *testing.T) {
		ln, err := client.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer ln.Close()
		assert.Equal(t, asUserID, socketOwner(t, addrPort(ln.Addr()), netip.AddrPort{}),
			"the forward's listener is not the user's")
	})

	t.Run("agent socket", func(t *testing.T) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		keyring := agent.NewKeyring()
		require.NoError(t, keyring.Add(agent.AddedKey{PrivateKey: priv}))
		require.NoError(t, agent.ForwardToAgent(client, keyring))
		sess, err := client.NewSession()
		require.NoError(t, err)
		defer sess.Close()
		require.NoError(t, agent.RequestAgentForwarding(sess))

		out, err := sess.Output(`stat -c '%u:%g' "$SSH_AUTH_SOCK" "${SSH_AUTH_SOCK%/*}"`)
		require.NoError(t, err, "the user cannot reach the agent socket: %s", out)
		assert.Equal(t, strings.Repeat(want+":"+want+"\n", 2), string(out), "socket, then its directory")
	})

	t.Run("signal", func(t *testing.T) {
		// Sent as the user, a signal reaches the user's own process, and not one that became root like a sudo.
		assert.True(t, signalReaches(t, client, os.Args[0]), "a signal to the user's own process got lost")
		assert.False(t, signalReaches(t, client, setuidCopy(t)), "a signal reached a process that became root")
	})
}

// Not a test: the process a signal is sent to. It turns fully root first when it runs setuid.
func TestSignalTarget(t *testing.T) {
	if !slices.Contains(os.Args, "signal-target") {
		t.Skip("only runs as the target of the signal check")
	}
	if os.Geteuid() == 0 {
		require.NoError(t, syscall.Setuid(0))
	}
	got := make(chan os.Signal, 1)
	signal.Notify(got, syscall.SIGUSR1)
	_, _ = os.Stdout.WriteString("ready\n")
	select {
	case <-got:
		_, _ = os.Stdout.WriteString("signaled\n")
	case <-time.After(30 * time.Second):
	}
}

func addUser(t *testing.T) {
	t.Helper()
	if exec.Command("getent", "passwd", asUser).Run() != nil {
		out, err := exec.Command("useradd", "--uid", strconv.Itoa(asUserID), "--user-group", "--create-home",
			"--shell", "/bin/sh", asUser).CombinedOutput()
		require.NoError(t, err, "useradd: %s", out)
	}
	t.Cleanup(func() { _ = exec.Command("userdel", "--remove", asUser).Run() })
}

func dialAsUser(t *testing.T) *ssh.Client {
	t.Helper()
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
	ca := newTestCA(t)
	srv, err := New(nil)
	require.NoError(t, err)
	a := testAccess(t, ca)
	a.Principals = map[string][]string{asUser: {testPrincipal}}
	srv.SetAccess(a)
	withPolicy(Policy{AllowForwarding: true, AllowAgentForwarding: true})(srv)
	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go srv.Serve(t.Context(), l)
	client, err := dial(t, l.Addr().String(), asUser, userCert(t, ca, testPrincipal))
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// assertIDs checks the Uid, Gid and Groups lines of /proc/<pid>/status: real, effective, saved and fs ids alike.
func assertIDs(t *testing.T, status, want string) {
	t.Helper()
	got := map[string][]string{}
	for _, m := range procIDs.FindAllStringSubmatch(status, -1) {
		got[m[1]] = strings.Fields(m[2])
	}
	assert.Equal(t, slices.Repeat([]string{want}, 4), got["Uid"], "uids in %q", status)
	assert.Equal(t, slices.Repeat([]string{want}, 4), got["Gid"], "gids in %q", status)
	assert.Equal(t, []string{want}, got["Groups"], "supplementary groups in %q", status)
}

// socketOwner reads the uid of a TCP socket from /proc/net/tcp. A zero remote matches a listener.
func socketOwner(t *testing.T, local, remote netip.AddrPort) int {
	t.Helper()
	f, err := os.Open("/proc/net/tcp")
	require.NoError(t, err)
	defer f.Close()
	lines := bufio.NewScanner(f)
	lines.Scan()
	for lines.Scan() {
		fields := strings.Fields(lines.Text())
		if len(fields) < 8 || procAddr(t, fields[1]) != local {
			continue
		}
		// 0A is LISTEN.
		if remote.IsValid() && procAddr(t, fields[2]) != remote || !remote.IsValid() && fields[3] != "0A" {
			continue
		}
		uid, convErr := strconv.Atoi(fields[7])
		require.NoError(t, convErr)
		return uid
	}
	require.FailNow(t, "no socket in /proc/net/tcp", "local %s, remote %s", local, remote)
	return -1
}

// procAddr parses 0100007F:1F90, the address in host byte order and the port in hex.
func procAddr(t *testing.T, field string) netip.AddrPort {
	t.Helper()
	ip, port, ok := strings.Cut(field, ":")
	require.True(t, ok, "address %q", field)
	raw, err := hex.DecodeString(ip)
	require.NoError(t, err)
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], binary.BigEndian.Uint32(raw))
	p, err := strconv.ParseUint(port, 16, 16)
	require.NoError(t, err)
	return netip.AddrPortFrom(netip.AddrFrom4(b), uint16(p))
}

// signalReaches starts bin as the session's command, sends it SIGUSR1 through the session and says if it arrived.
func signalReaches(t *testing.T, client *ssh.Client, bin string) bool {
	t.Helper()
	sess, err := client.NewSession()
	require.NoError(t, err)
	defer sess.Close()
	stdout, err := sess.StdoutPipe()
	require.NoError(t, err)
	var stderr strings.Builder
	sess.Stderr = &stderr
	require.NoError(t, sess.Start("exec '"+bin+"' '-test.run=^TestSignalTarget$' -- signal-target"))

	lines := make(chan string, 2)
	go func() {
		s := bufio.NewScanner(stdout)
		for s.Scan() {
			lines <- s.Text()
		}
		close(lines)
	}()
	select {
	case line := <-lines:
		require.Equal(t, "ready", line, "stderr: %s", &stderr)
	case <-time.After(10 * time.Second):
		require.FailNow(t, "the signal target never started", "stderr: %s", &stderr)
	}
	require.NoError(t, sess.Signal(ssh.SIGUSR1))
	select {
	case line := <-lines:
		return line == "signaled"
	case <-time.After(3 * time.Second):
		return false
	}
}

// setuidCopy is the test binary owned by root with the setuid bit, in a directory the user can reach.
func setuidCopy(t *testing.T) string {
	t.Helper()
	//nolint:usetesting // the parent of t.TempDir() is root-only, the user could not reach the binary
	dir, err := os.MkdirTemp("", "nokku-signal-target-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	require.NoError(t, os.Chmod(dir, 0o755))
	bin := filepath.Join(dir, "signal-target")
	data, err := os.ReadFile(os.Args[0])
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(bin, data, 0o755))
	require.NoError(t, os.Chmod(bin, 0o755|os.ModeSetuid))
	return bin
}
