package sshd

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestBinaryInterop(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	bin := buildTestServer(t)

	ca := newTestCA(t)
	configDir := t.TempDir()
	// Written in the daemon's on-disk format, not via Cache.Save, so the harness stays independent of state wiring.
	must.NoError(writeCacheFile(configDir, ca.pub, currentUser(t), []string{testPrincipal}), "seed cache")

	cmd := exec.Command(
		bin,
		"--config-dir", configDir,
		"--addr", "127.0.0.1:0",
		"--allow-nonroot",
	)
	stdout, err := cmd.StdoutPipe()
	must.NoError(err)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	must.NoError(cmd.Start(), "start sshd-server")
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	addr := readLine(t, stdout, 10*time.Second)
	t.Logf("headless server on %s", addr)
	host, port := hostPort(t, addr)

	user := currentUser(t)
	identity := userCertFile(t, ca)
	known := filepath.Join(t.TempDir(), "known_hosts")
	baseOpts := []string{
		"-p", port,
		"-i", identity,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=" + known,
	}
	// scp/sftp take the port as -P, ssh/rsync/git take -p.
	fileOpts := []string{
		"-P", port,
		"-i", identity,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=" + known,
	}

	scratch := homeScratch(t)
	payload := []byte("interop payload\n")

	// 1. ssh exec
	out, err := runCmd(
		"ssh",
		append(baseOpts, "-q", fmt.Sprintf("%s@%s", user, host), "echo hello")...,
	)
	must.NoError(err, "ssh exec: %s", out)
	is.Equal("hello\n", string(out))

	// 2. scp -O (legacy)
	src := filepath.Join(scratch, "legacy.txt")
	must.NoError(os.WriteFile(src, payload, 0o644), "write scp source")
	up := filepath.Join(scratch, "legacy-up.txt")
	out, err = runCmd(
		"scp",
		append(fileOpts, "-O", src, fmt.Sprintf("%s@%s:%s", user, host, up))...,
	)
	must.NoError(err, "scp -O up: %s", out)
	var b []byte
	b, err = os.ReadFile(up)
	must.NoError(err, "read scp -O upload")
	is.Equal(string(payload), string(b))

	// 3. scp -s (SFTP-based modern)
	down := filepath.Join(scratch, "modern-down.txt")
	out, err = runCmd(
		"scp",
		append(fileOpts, "-s", fmt.Sprintf("%s@%s:%s", user, host, src), down)...,
	)
	must.NoError(err, "scp -s down: %s", out)
	b, err = os.ReadFile(down)
	must.NoError(err, "read scp -s download")
	is.Equal(string(payload), string(b))

	// 4. sftp batch
	sftpOps := fmt.Sprintf("get %s %s\nbye\n", src, filepath.Join(scratch, "sftp-down.txt"))
	out, err = runCmdWithInput(
		"sftp",
		sftpOps,
		append(fileOpts, "-b", "-", fmt.Sprintf("%s@%s", user, host))...,
	)
	must.NoError(err, "sftp: %s", out)
	b, err = os.ReadFile(filepath.Join(scratch, "sftp-down.txt"))
	must.NoError(err, "read sftp download")
	is.Equal(string(payload), string(b))

	// 5. rsync
	rsrc := filepath.Join(t.TempDir(), "rsync.txt")
	must.NoError(os.WriteFile(rsrc, payload, 0o600), "write rsync source")
	sshOpts := fmt.Sprintf("ssh %s", strings.Join(baseOpts, " "))
	out, err = runCmd(
		"rsync",
		"-e",
		sshOpts,
		rsrc,
		fmt.Sprintf("%s@%s:%s", user, host, filepath.Join(scratch, "rsync.txt")),
	)
	must.NoError(err, "rsync: %s", out)
	b, err = os.ReadFile(filepath.Join(scratch, "rsync.txt"))
	must.NoError(err, "read rsync copy")
	is.Equal(string(payload), string(b))

	// 6. git clone/push over the embedded server
	gitDir := filepath.Join(t.TempDir(), "repo.git")
	runGit(t, "init", "--bare", gitDir)
	gitSSH := fmt.Sprintf(
		"ssh %s",
		strings.Join(append([]string{"-o", "IdentitiesOnly=yes"}, baseOpts...), " "),
	)
	work := filepath.Join(t.TempDir(), "work")
	runGit(
		t,
		"-c",
		"core.sshCommand="+gitSSH,
		"clone",
		fmt.Sprintf("%s@%s:%s", user, host, gitDir),
		work,
	)
	must.NoError(os.WriteFile(filepath.Join(work, "f.txt"), []byte("git\n"), 0o644), "write git file")
	runGit(t, "-C", work, "-c", "core.sshCommand="+gitSSH, "add", "f.txt")
	runGit(
		t,
		"-C",
		work,
		"-c",
		"user.name=interop",
		"-c",
		"user.email=interop@test",
		"commit",
		"-m",
		"add f",
	)
	runGit(t, "-C", work, "-c", "core.sshCommand="+gitSSH, "push", "origin", "HEAD")

	// 7. -L forward through the real binary
	echo := testEchoServer(t)
	defer echo.Close()
	_, echoPortStr, _ := net.SplitHostPort(echo.Addr().String())
	localPort := freePort(t)
	fwd := exec.Command("ssh", append(
		baseOpts,
		"-L", fmt.Sprintf("%s:127.0.0.1:%s", localPort, echoPortStr),
		"-N", "-q",
		fmt.Sprintf("%s@%s", user, host),
	)...)
	must.NoError(fwd.Start(), "start ssh -L")
	defer func() {
		_ = fwd.Process.Kill()
		_, _ = fwd.Process.Wait()
	}()

	var fconn net.Conn
	is.Eventually(func() bool {
		fconn, err = net.Dial("tcp", "127.0.0.1:"+localPort)
		return err == nil
	}, 10*time.Second, 50*time.Millisecond)
	must.NoError(err, "could not connect to local -L port %s", localPort)
	defer fconn.Close()
	_, err = fconn.Write([]byte("forward"))
	must.NoError(err, "-L write")
	_ = fconn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 7)
	_, err = io.ReadFull(fconn, buf)
	must.NoError(err, "-L read")
	is.Equal("forward", string(buf))

	// 8. -A agent forwarding. CI runners have no SSH_AUTH_SOCK, so a dedicated ssh-agent is started.
	sock, stopAgent := testAgent(t)
	defer stopAgent()
	agentSSH := exec.Command(
		"ssh",
		append(baseOpts, "-A", fmt.Sprintf("%s@%s", user, host), "echo $SSH_AUTH_SOCK")...,
	)
	agentSSH.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sock)
	aout, aerr := agentSSH.CombinedOutput()
	must.NoError(aerr, "ssh -A: %s", aout)
	is.NotEmpty(strings.TrimSpace(string(aout)), "ssh -A did not expose SSH_AUTH_SOCK")

	// 9. Audit events were logged for the clients above. Wait reaps the server and finishes the stderr copy.
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	is.Contains(stderr.String(), "type=auth_success")
	is.Contains(stderr.String(), "type=command")
}

func writeCacheFile(configDir string, ca ssh.PublicKey, username string, uuids []string) error {
	data, err := json.MarshalIndent(map[string]any{
		"principals": map[string][]string{username: uuids},
		"ca":         string(ssh.MarshalAuthorizedKey(ca)),
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(configDir, "cache.json"), data, 0o600)
}

func buildTestServer(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not installed")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "sshd-testserver")
	cmd := exec.Command("go", "build", "-o", bin, "./internal/sshd/testserver")
	cmd.Dir = repoRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot build the test ssh server: %v\n%s", err, out)
	}
	return bin
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

func readLine(t *testing.T, r io.Reader, timeout time.Duration) string {
	t.Helper()
	type result struct {
		line string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		var b strings.Builder
		buf := make([]byte, 1)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				b.Write(buf[:n])
				if buf[0] == '\n' {
					ch <- result{b.String(), nil}
					return
				}
			}
			if err != nil {
				ch <- result{b.String(), err}
				return
			}
		}
	}()
	select {
	case r := <-ch:
		return strings.TrimSpace(r.line)
	case <-time.After(timeout):
		t.Fatal("timed out waiting for server address")
		return ""
	}
}

func runCmd(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

func runCmdWithInput(name, input string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(input)
	return cmd.CombinedOutput()
}

func runGit(t *testing.T, args ...string) {
	t.Helper()
	out, err := exec.Command("git", args...).CombinedOutput()
	require.NoError(t, err, "git %v: %s", args, out)
}

// A dedicated ssh-agent keeps the -A check independent of the host's environment.
func testAgent(t *testing.T) (string, func()) {
	t.Helper()
	if _, err := exec.LookPath("ssh-agent"); err != nil {
		t.Skip("ssh-agent not installed")
	}
	out, err := exec.Command("ssh-agent").CombinedOutput()
	require.NoError(t, err, "start ssh-agent: %s", out)
	var sock, pid string
	for line := range strings.SplitSeq(string(out), "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || !strings.HasPrefix(val, "/") {
			continue
		}
		val = strings.SplitN(val, ";", 2)[0]
		switch key {
		case "SSH_AUTH_SOCK":
			sock = val
		case "SSH_AGENT_PID":
			pid = val
		}
	}
	if sock == "" {
		t.Fatalf("ssh-agent did not report SSH_AUTH_SOCK: %s", out)
	}
	stop := func() {
		if pid != "" {
			_ = exec.Command("kill", pid).Run()
		}
	}
	return sock, stop
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return port
}
