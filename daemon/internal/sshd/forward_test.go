package sshd

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func testEchoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "echo listen")
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln
}

func TestServerDirectTCPIP(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{Policy: Policy{AllowForwarding: true}})
	defer closeFn()

	echo := testEchoServer(t)
	defer echo.Close()
	_, portStr, _ := net.SplitHostPort(echo.Addr().String())

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	conn, err := client.Dial("tcp", "127.0.0.1:"+portStr)
	must.NoError(err, "forward dial")
	defer conn.Close()

	_, err = conn.Write([]byte("ping"))
	must.NoError(err, "write")
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	must.NoError(err, "read")
	is.Equal("ping", string(buf))
}

func TestServerMaxChannelsHeldForRelay(t *testing.T) {
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{Policy: Policy{AllowForwarding: true}},
		func(s *Server) { s.maxChannels = 1 })
	defer closeFn()

	echo := testEchoServer(t)
	defer echo.Close()
	_, portStr, _ := net.SplitHostPort(echo.Addr().String())

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	first, err := client.Dial("tcp", "127.0.0.1:"+portStr)
	must.NoError(err, "first forward")

	_, err = client.Dial("tcp", "127.0.0.1:"+portStr)
	must.Error(err, "second forward accepted while the cap was held")

	_ = first.Close()
	must.Eventually(func() bool {
		conn, derr := client.Dial("tcp", "127.0.0.1:"+portStr)
		if derr != nil {
			return false
		}
		_ = conn.Close()
		return true
	}, 5*time.Second, 20*time.Millisecond, "channel slot never released")
}

func TestServerDirectTCPIPDisabled(t *testing.T) {
	is := assert.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	echo := testEchoServer(t)
	defer echo.Close()
	_, portStr, _ := net.SplitHostPort(echo.Addr().String())

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	require.NoError(t, err, "dial")
	defer client.Close()

	_, err = client.Dial("tcp", "127.0.0.1:"+portStr)
	is.Error(err, "forwarding unexpectedly allowed")
}

func TestServerRemoteForward(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{Policy: Policy{AllowForwarding: true}})
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	ln, err := client.Listen("tcp", "127.0.0.1:0")
	must.NoError(err, "remote listen")
	defer ln.Close()

	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()

	sconn, err := net.Dial("tcp", ln.Addr().String())
	must.NoError(err, "dial server-side forward")
	defer sconn.Close()

	_, err = sconn.Write([]byte("pong"))
	must.NoError(err, "write")
	_ = sconn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4)
	_, err = io.ReadFull(sconn, buf)
	must.NoError(err, "read")
	is.Equal("pong", string(buf))
}

func TestServerRemoteForwardPortZero(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{Policy: Policy{AllowForwarding: true}})
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	first, err := client.Listen("tcp", "127.0.0.1:0")
	must.NoError(err, "first port 0 forward")
	second, err := client.Listen("tcp", "127.0.0.1:0")
	must.NoError(err, "second port 0 forward")
	defer second.Close()
	is.NotEqual(first.Addr().String(), second.Addr().String())

	must.NoError(first.Close(), "cancel the first forward")
	_, err = net.DialTimeout("tcp", first.Addr().String(), time.Second)
	is.Error(err, "the cancelled forward still listens")
}

// The cancel names the address the client asked for, so a policy change in between must not strand the listener.
func TestServerRemoteForwardCancelAfterPolicyChange(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	var srv *Server
	addr, closeFn := startTestServerOpts(t, ca, Options{Policy: Policy{AllowForwarding: true}},
		func(s *Server) { srv = s })
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	ln, err := client.Listen("tcp", "0.0.0.0:0")
	must.NoError(err, "forward")
	srv.SetPolicy(Policy{AllowForwarding: true, GatewayPorts: true})
	must.NoError(ln.Close(), "cancel the forward")

	_, port, err := net.SplitHostPort(ln.Addr().String())
	must.NoError(err)
	_, err = net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), time.Second)
	is.Error(err, "the cancelled forward still listens")
}

func TestServerRemoteForwardListenersCapped(t *testing.T) {
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{Policy: Policy{AllowForwarding: true}},
		func(s *Server) { s.maxChannels = 2 })
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	first, err := client.Listen("tcp", "127.0.0.1:0")
	must.NoError(err, "first forward")
	second, err := client.Listen("tcp", "127.0.0.1:0")
	must.NoError(err, "second forward")
	defer second.Close()

	_, err = client.Listen("tcp", "127.0.0.1:0")
	must.Error(err, "third forward accepted past the cap")

	must.NoError(first.Close(), "cancel the first forward")
	must.Eventually(func() bool {
		ln, lerr := client.Listen("tcp", "127.0.0.1:0")
		if lerr != nil {
			return false
		}
		_ = ln.Close()
		return true
	}, 5*time.Second, 20*time.Millisecond, "a cancelled forward never released its slot")
}

// Clients key a forward by the address they asked for, so the server must report "localhost" back verbatim.
func TestServerRemoteForwardLocalhost(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{Policy: Policy{AllowForwarding: true}})
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	ln, err := client.Listen("tcp", "localhost:0")
	must.NoError(err, "remote listen")
	defer ln.Close()

	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()

	sconn, err := net.Dial("tcp", ln.Addr().String())
	must.NoError(err, "dial server-side forward")
	defer sconn.Close()

	_, err = sconn.Write([]byte("pong"))
	must.NoError(err, "write")
	_ = sconn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4)
	_, err = io.ReadFull(sconn, buf)
	must.NoError(err, "read")
	is.Equal("pong", string(buf))
}

func TestServerRemoteForwardInterop(t *testing.T) {
	if !isTestBinary() {
		t.Skip("requires the test binary on PATH")
	}
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("ssh not installed")
	}

	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{Policy: Policy{AllowForwarding: true}})
	defer closeFn()
	host, port := hostPort(t, addr)

	echo := testEchoServer(t)
	defer echo.Close()
	_, echoPortStr, _ := net.SplitHostPort(echo.Addr().String())

	// Picks a free port for -R to bind on the server side.
	bound, err := net.Listen("tcp", "127.0.0.1:0")
	must.NoError(err)
	_, boundPortStr, _ := net.SplitHostPort(bound.Addr().String())
	_ = bound.Close()

	user := currentUser(t)
	identity := userCertFile(t, ca)

	// ssh -R <boundPort>:<echoHost>:<echoPort> -N
	cmd := exec.Command(
		sshBin,
		"-p", port,
		"-i", identity,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-R", fmt.Sprintf("%s:127.0.0.1:%s", boundPortStr, echoPortStr),
		"-N",
		fmt.Sprintf("%s@%s", user, host),
	)
	stderr, err := cmd.StderrPipe()
	must.NoError(err)
	must.NoError(cmd.Start(), "start ssh")
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()
	// Give the forward a moment to be established.
	time.Sleep(500 * time.Millisecond)

	sconn, err := net.Dial("tcp", "127.0.0.1:"+boundPortStr)
	if err != nil {
		must.NoError(err, "dial server-side forward\n%s", slurpAfterKill(cmd, stderr))
	}
	defer sconn.Close()

	_, err = sconn.Write([]byte("interop"))
	must.NoError(err, "write")
	_ = sconn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 7)
	_, err = io.ReadFull(sconn, buf)
	if err != nil {
		must.NoError(err, "read\n%s", slurpAfterKill(cmd, stderr))
	}
	is.Equal("interop", string(buf))
}

// ssh -N never exits on its own, so reading its stderr blocks forever unless it is killed first.
func slurpAfterKill(cmd *exec.Cmd, stderr io.Reader) string {
	_ = cmd.Process.Kill()
	b, _ := io.ReadAll(stderr)
	_, _ = cmd.Process.Wait()
	return string(b)
}

// Matches OpenSSH's GatewayPorts=no default.
func TestForwardAddr(t *testing.T) {
	tests := []struct {
		name      string
		requested string
		gateway   bool
		want      string
	}{
		{"empty request pins loopback", "", false, "127.0.0.1:22"},
		{"wildcard request pins loopback", "0.0.0.0", false, "127.0.0.1:22"},
		{"lan request pins loopback", "192.168.1.5", false, "127.0.0.1:22"},
		{"empty request with gateway binds wildcard", "", true, "0.0.0.0:22"},
		{"lan request with gateway binds lan", "192.168.1.5", true, "192.168.1.5:22"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := assert.New(t)
			is.Equal(tt.want, forwardAddr(tcpipForwardData{BindAddr: tt.requested, BindPort: 22}, tt.gateway))
		})
	}
}

func TestServerForwardingLargeTransfer(t *testing.T) {
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{Policy: Policy{AllowForwarding: true}})
	defer closeFn()

	payload := bytes.Repeat([]byte("0123456789abcdef"), 512*1024) // 8 MiB
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must.NoError(err, "listen")
	defer ln.Close()
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer c.Close()
		if _, copyErr := io.Copy(io.Discard, c); copyErr != nil {
			t.Errorf("server read: %v", copyErr)
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	conn, err := client.Dial("tcp", "127.0.0.1:"+portStr)
	must.NoError(err, "forward dial")
	defer conn.Close()

	_, err = conn.Write(payload)
	must.NoError(err, "write")
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	// The server side discards. Give it a moment, then confirm no error.
	time.Sleep(200 * time.Millisecond)
}

// A forward request racing connection teardown must not leak a listener.
func TestTCPIPForwardAfterClose(t *testing.T) {
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
	srv, err := New(Options{Principals: func(string) []string { return nil }, Policy: Policy{AllowForwarding: true}})
	require.NoError(t, err)
	defer srv.hostKeyDev.Close()

	conn := &ssh.ServerConn{Permissions: &ssh.Permissions{
		Extensions: map[string]string{"permit-port-forwarding": ""},
	}}
	st := newConnState(conn, 1)
	st.close()
	ok, _ := srv.tcpipForward(st, ssh.Marshal(tcpipForwardData{BindAddr: "127.0.0.1", BindPort: 0}))
	assert.False(t, ok)
}

func TestDialAsReportsTheDialError(t *testing.T) {
	sysUser, err := lookupAccount(currentUser(t))
	require.NoError(t, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closed := ln.Addr().String()
	require.NoError(t, ln.Close())

	_, err = dialAs(sysUser, closed)
	require.ErrorContains(t, err, "connection refused", "the client is told why a forward failed")

	// A cut address could name another host than the one in the audit log.
	_, err = dialAs(sysUser, strings.Repeat("a", maxForwardAddr+1))
	require.ErrorContains(t, err, "too long")
}

// The point of the helper: to the kernel a forward is the user's socket, not the daemon's.
func TestForwardSocketsBelongToTheUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("test must run as root")
	}
	const nobody = 65534
	sysUser := &account{Name: "nobody", UID: nobody, GID: nobody, Home: "/"}
	helperForEveryone(t)

	ln, err := listenAs(sysUser, "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	assert.Equal(t, nobody, tcpSocketUID(t, ln.Addr()), "listener of a remote forward")

	c, err := dialAs(sysUser, ln.Addr().String())
	require.NoError(t, err)
	defer c.Close()
	assert.Equal(t, nobody, tcpSocketUID(t, c.LocalAddr()), "connection of a direct forward")
}

// The go tool builds the test binary in a directory only its own user can enter. nokkud itself is in /usr/bin.
func helperForEveryone(t *testing.T) {
	t.Helper()
	//nolint:usetesting // t.TempDir() sits under a 0700 directory
	dir, err := os.MkdirTemp("", "nokkud-helper-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	require.NoError(t, os.Chmod(dir, 0o755))

	bin := filepath.Join(dir, filepath.Base(os.Args[0]))
	data, err := os.ReadFile(os.Args[0])
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(bin, data, 0o755))

	inPlace := helperArgv
	t.Cleanup(func() { helperArgv = inPlace })
	helperArgv = func(name string, args ...string) ([]string, error) {
		return append([]string{bin, "-test.run=^TestHelperProcess$", "--", name}, args...), nil
	}
}

// The uid column of /proc/net/tcp is the owner a firewall matches on.
func tcpSocketUID(t *testing.T, local net.Addr) int {
	t.Helper()
	ap := addrPort(local)
	want := fmt.Sprintf("%08X:%04X", binary.LittleEndian.Uint32(ap.Addr().AsSlice()), ap.Port())
	data, err := os.ReadFile("/proc/net/tcp")
	require.NoError(t, err)
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 7 && fields[1] == want {
			uid, convErr := strconv.Atoi(fields[7])
			require.NoError(t, convErr)
			return uid
		}
	}
	t.Fatalf("no socket on %s in /proc/net/tcp", local)
	return 0
}
