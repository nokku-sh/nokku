package sshd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"testing"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func init() {
	helperArgv = func(name string, args ...string) ([]string, error) {
		return append(testHelperArgv(os.Args[0], name), args...), nil
	}
}

// helperCmd clears the env, so GORACE goes in through env(1). A race build otherwise sleeps 1s on every exit.
func testHelperArgv(bin, name string) []string {
	return []string{"/usr/bin/env", "GORACE=atexit_sleep_ms=0", bin, "-test.run=^TestHelperProcess$", "--", name}
}

// Not a test: the binary re-entered as a helper, see the helperArgv override in init.
func TestHelperProcess(t *testing.T) {
	i := slices.Index(os.Args, "--")
	if i < 0 || i+1 >= len(os.Args) {
		return
	}
	if err := RunHelper(t.Context(), os.Args[i+1], os.Args[i+2:]); err != nil {
		fmt.Fprintln(os.Stderr, "helper:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

// The SFTP server roots at the user's real home like sshd, so tests use a scratch dir under it.
func sftpClient(t *testing.T, ca testCA) (*sftp.Client, func()) {
	t.Helper()
	must := require.New(t)
	addr, closeFn := startTestServer(t, ca)

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	if err != nil {
		closeFn()
	}
	must.NoError(err)

	sc, err := sftp.NewClient(client)
	if err != nil {
		client.Close()
		closeFn()
	}
	must.NoError(err)
	return sc, func() {
		sc.Close()
		client.Close()
		closeFn()
	}
}

func homeScratch(t *testing.T) string {
	t.Helper()
	must := require.New(t)
	cur, err := user.Current()
	must.NoError(err)
	//nolint:usetesting // must live under the real home. t.TempDir() is /tmp
	dir, err := os.MkdirTemp(cur.HomeDir, ".nokkud-sftp-test-*")
	must.NoError(err, "scratch dir under %s", cur.HomeDir)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestServerSFTPTransfer(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	scratch := homeScratch(t)
	sc, closeFn := sftpClient(t, ca)
	defer closeFn()

	payload := []byte("hello nokkud sftp")
	path := filepath.Join(scratch, "hello.txt")
	f, err := sc.Create(path)
	must.NoError(err)
	_, err = f.Write(payload)
	must.NoError(err)
	must.NoError(f.Close())

	got, err := os.ReadFile(path)
	must.NoError(err)
	is.Equal(payload, got)

	r, err := sc.Open(path)
	must.NoError(err)
	data, err := io.ReadAll(r)
	must.NoError(err)
	_ = r.Close()
	is.Equal(payload, data)

	entries, err := sc.ReadDir(scratch)
	must.NoError(err)
	must.Len(entries, 1)
	is.Equal("hello.txt", entries[0].Name())
}

func TestServerSFTPOps(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	scratch := homeScratch(t)
	sc, closeFn := sftpClient(t, ca)
	defer closeFn()

	must.NoError(sc.Mkdir(filepath.Join(scratch, "sub")))
	must.NoError(sc.Rename(
		filepath.Join(scratch, "sub"),
		filepath.Join(scratch, "renamed"),
	))
	info, err := sc.Stat(filepath.Join(scratch, "renamed"))
	must.NoError(err)
	is.True(info.IsDir(), "expected directory, got %v", info.Mode())
	must.NoError(sc.RemoveDirectory(filepath.Join(scratch, "renamed")))

	_, err = sc.Stat(filepath.Join(scratch, "renamed"))
	is.Error(err, "expected stat to fail after rmdir")
}

func TestServerSFTPWorkingDir(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	home := currentHome(t)
	sc, closeFn := sftpClient(t, ca)
	defer closeFn()

	wd, err := sc.Getwd()
	must.NoError(err)
	is.Equal(home, wd)

	must.NoError(sc.Mkdir("nokkud-rel-test"))
	defer func() { _ = os.RemoveAll(filepath.Join(home, "nokkud-rel-test")) }()
	_, err = os.Stat(filepath.Join(home, "nokkud-rel-test"))
	must.NoError(err, "relative dir not created under home")
}

func TestServerSCPModern(t *testing.T) {
	scp, err := exec.LookPath("scp")
	if err != nil {
		t.Skip("scp not installed")
	}
	if !isTestBinary() {
		t.Fatal("TestServerSCPModern requires running under the test binary")
	}

	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	scratch := homeScratch(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	payload := []byte("scp modern mode\n")
	src := filepath.Join(t.TempDir(), "in.txt")
	must.NoError(os.WriteFile(src, payload, 0o600))

	host, port := hostPort(t, addr)
	user := currentUser(t)
	dst := fmt.Sprintf("%s@%s:%s", user, host, filepath.Join(scratch, "copied.txt"))

	cmd := exec.Command(
		scp,
		"-s",
		"-P", port,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR",
		"-i", userCertFile(t, ca),
		src,
		dst,
	)
	out, err := cmd.CombinedOutput()
	must.NoError(err, "scp failed: %s", out)

	got, err := os.ReadFile(filepath.Join(scratch, "copied.txt"))
	must.NoError(err)
	is.Equal(payload, got)
}

func TestServerRsync(t *testing.T) {
	rsync, err := exec.LookPath("rsync")
	if err != nil {
		t.Skip("rsync not installed")
	}
	if !isTestBinary() {
		t.Fatal("TestServerRsync requires running under the test binary")
	}

	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	scratch := homeScratch(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	payload := []byte("rsync over nokkud\n")
	src := filepath.Join(t.TempDir(), "data.txt")
	must.NoError(os.WriteFile(src, payload, 0o600))

	host, port := hostPort(t, addr)
	user := currentUser(t)
	remote := fmt.Sprintf("%s@%s:%s", user, host, filepath.Join(scratch, "data.txt"))
	sshOpts := fmt.Sprintf(
		"ssh -p %s -i %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
		port,
		userCertFile(t, ca),
	)

	cmd := exec.Command(
		rsync,
		"-e", sshOpts,
		src,
		remote,
	)
	out, err := cmd.CombinedOutput()
	must.NoError(err, "rsync failed: %s", out)

	got, err := os.ReadFile(filepath.Join(scratch, "data.txt"))
	must.NoError(err)
	is.Equal(payload, got)
}

func TestServerGit(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	if !isTestBinary() {
		t.Fatal("TestServerGit requires running under the test binary")
	}

	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	scratch := homeScratch(t)
	repo := filepath.Join(scratch, "repo.git")
	must.NoError(os.MkdirAll(repo, 0o700))
	out, err := exec.Command(git, "init", "--bare", repo).CombinedOutput()
	must.NoError(err, "git init: %s", out)

	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	host, port := hostPort(t, addr)
	user := currentUser(t)
	key := userCertFile(t, ca)

	work := t.TempDir()
	write := func(p, c string) {
		must.NoError(os.WriteFile(filepath.Join(work, p), []byte(c), 0o600), "write %s", p)
	}
	run := func(name string, args ...string) {
		c := exec.Command(name, args...)
		c.Dir = work
		cout, cerr := c.CombinedOutput()
		must.NoError(cerr, "%s %v: %s", name, args, cout)
	}
	run("git", "init", "-q")
	write("a.txt", "git over nokkud\n")
	run("git", "add", "a.txt")
	run(
		"git",
		"-c",
		"user.email=test@nokku.sh",
		"-c",
		"user.name=test",
		"commit",
		"-q",
		"-m",
		"init",
	)

	sshCmd := fmt.Sprintf(
		"ssh -p %s -i %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
		port,
		key,
	)
	url := fmt.Sprintf("ssh://%s@%s/%s", user, host, repo)
	push := exec.Command(git, "push", "-q", url, "HEAD:main")
	push.Dir = work
	push.Env = append(os.Environ(), "GIT_SSH_COMMAND="+sshCmd)
	out, err = push.CombinedOutput()
	must.NoError(err, "git push: %s", out)

	verify := exec.Command(git, "rev-parse", "HEAD")
	verify.Dir = work
	head, err := verify.Output()
	must.NoError(err)
	head = bytes.TrimSpace(head)
	show := exec.Command(git, "show-ref", "refs/heads/main")
	show.Dir = repo
	out, err = show.Output()
	must.NoError(err, "remote ref missing: %s", out)
	is.True(bytes.Contains(out, head), "remote ref %q not pushed, show-ref = %q", head, out)
}

func hostPort(t *testing.T, addr string) (string, string) {
	t.Helper()
	must := require.New(t)
	host, port, err := net.SplitHostPort(addr)
	must.NoError(err, "split %s", addr)
	return host, port
}

func currentHome(t *testing.T) string {
	t.Helper()
	must := require.New(t)
	cur, err := user.Current()
	must.NoError(err)
	return cur.HomeDir
}

// Returns the path to the private key (scp -i).
func userCertFile(t *testing.T, ca testCA) string {
	t.Helper()
	must := require.New(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	must.NoError(err)
	pub, err := ssh.NewPublicKey(priv.Public())
	must.NoError(err)
	cert := &ssh.Certificate{
		Key:             pub,
		CertType:        ssh.UserCert,
		KeyId:           "test-user",
		ValidPrincipals: []string{testPrincipal},
		ValidAfter:      0,
		ValidBefore:     ssh.CertTimeInfinity,
		Extensions:      maps.Clone(defaultExtensions),
	}
	must.NoError(cert.SignCert(rand.Reader, ca.signer))

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	privBlock, err := ssh.MarshalPrivateKey(priv, "")
	must.NoError(err)
	must.NoError(os.WriteFile(keyPath, pem.EncodeToMemory(privBlock), 0o600))

	certPath := keyPath + "-cert.pub"
	certPub := ssh.MarshalAuthorizedKey(cert)
	must.NoError(os.WriteFile(certPath, certPub, 0o600))
	return keyPath
}

func isTestBinary() bool {
	return filepath.Base(os.Args[0]) == "sshd.test"
}

// Like under sshd, a lock shell stops SFTP too. The subsystem must not start beside the shell.
func TestServerSFTPRefusedByLockShell(t *testing.T) {
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{}, func(s *Server) {
		lookup := s.lookupAccount
		s.lookupAccount = func(name string) (*account, error) {
			account, err := lookup(name)
			if err == nil {
				account.Shell = "/bin/false"
			}
			return account, err
		}
	})
	defer closeFn()
	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	require.NoError(t, err, "dial")
	defer client.Close()

	_, err = sftp.NewClient(client)
	require.Error(t, err, "sftp got past a lock shell")
}
