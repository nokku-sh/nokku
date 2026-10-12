package sshd

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func agentForwardedSession(t *testing.T, ca testCA) *ssh.Session {
	t.Helper()
	must := require.New(t)
	addr, closeFn := startTestServerOpts(
		t,
		ca,
		Options{Policy: Policy{AllowAgentForwarding: true}},
	)
	t.Cleanup(closeFn)

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err)
	t.Cleanup(func() { _ = client.Close() })

	// Client side: an in-memory agent that holds one key serves the auth-agent@openssh.com channels.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	must.NoError(err)
	keyring := agent.NewKeyring()
	must.NoError(keyring.Add(agent.AddedKey{PrivateKey: priv}))
	must.NoError(agent.ForwardToAgent(client, keyring))

	sess, err := client.NewSession()
	must.NoError(err)
	t.Cleanup(func() { _ = sess.Close() })
	must.NoError(agent.RequestAgentForwarding(sess))
	return sess
}

func TestServerAgentForwarding(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	sess := agentForwardedSession(t, ca)

	out, err := sess.Output("echo $SSH_AUTH_SOCK")
	must.NoError(err)
	is.NotEmpty(out, "SSH_AUTH_SOCK not set in session")
	t.Logf("SSH_AUTH_SOCK=%s", out)
}

func TestServerAgentForwardingKeyList(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	sess := agentForwardedSession(t, ca)

	// The helper flag goes through the shell, the daemon's env whitelist refuses GO_* from clients.
	helper := "GO_WANT_AGENT_HELPER_PROCESS=1 " + helperProcessCommand(t, "agent")
	out, err := sess.Output(helper)
	must.NoError(err, "agent helper: %s", out)
	is.Equal("keys=1\n", string(out))
}

func helperProcessCommand(t *testing.T, name string) string {
	t.Helper()
	return fmt.Sprintf("%s -test.run=TestAgentHelperProcess -- %s", sshdTestBinary(t), name)
}

func sshdTestBinary(t *testing.T) string {
	t.Helper()
	must := require.New(t)
	bin := os.Args[0]
	must.Equal("sshd.test", filepath.Base(bin), "expected test binary named sshd.test, got %q", bin)
	return bin
}

// Not a test: the binary re-entered as an agent client that prints the key count.
func TestAgentHelperProcess(_ *testing.T) {
	if os.Getenv("GO_WANT_AGENT_HELPER_PROCESS") != "1" {
		return
	}
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		fmt.Fprintln(os.Stderr, "SSH_AUTH_SOCK not set")
		os.Exit(2)
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		fmt.Fprintln(os.Stderr, "agent dial:", err)
		os.Exit(1)
	}
	ag := agent.NewClient(conn)
	keys, err := ag.List()
	_ = conn.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, "agent list:", err)
		os.Exit(1)
	}
	fmt.Printf("keys=%d\n", len(keys))
	os.Exit(0)
}

func TestServerAgentForwardingDisabled(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err)
	defer client.Close()

	sess, err := client.NewSession()
	must.NoError(err)
	defer sess.Close()
	err = agent.RequestAgentForwarding(sess)
	is.Error(err, "agent forwarding unexpectedly allowed")
}

func TestServerAgentForwardingInterop(t *testing.T) {
	if !isTestBinary() {
		t.Skip("requires the test binary on PATH")
	}
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("ssh not installed")
	}
	if _, err = exec.LookPath("ssh-add"); err != nil {
		t.Skip("ssh-add not installed")
	}

	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(
		t,
		ca,
		Options{Policy: Policy{AllowAgentForwarding: true}},
	)
	defer closeFn()
	host, port := hostPort(t, addr)
	user := currentUser(t)

	client, err := dial(t, addr, user, userCert(t, ca, testPrincipal))
	must.NoError(err)
	defer client.Close()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	must.NoError(err)
	keyring := agent.NewKeyring()
	must.NoError(keyring.Add(agent.AddedKey{PrivateKey: priv}))
	must.NoError(agent.ForwardToAgent(client, keyring))

	// ssh forwards its own agent, so one is started here. CI runners have none and would silently drop -A.
	sock, stopAgent := testAgent(t)
	defer stopAgent()
	agentEnv := append(os.Environ(), "SSH_AUTH_SOCK="+sock)
	keyFile := filepath.Join(t.TempDir(), "id_ed25519")
	out, err := exec.Command(
		"ssh-keygen", "-t", "ed25519", "-f", keyFile, "-N", "", "-q",
	).CombinedOutput()
	must.NoError(err, "ssh-keygen: %s", out)
	add := exec.Command("ssh-add", keyFile)
	add.Env = agentEnv
	out, err = add.CombinedOutput()
	must.NoError(err, "ssh-add: %s", out)

	identity := userCertFile(t, ca)
	cmd := exec.Command(
		sshBin,
		"-A",
		"-p", port,
		"-i", identity,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		fmt.Sprintf("%s@%s", user, host),
		"ssh-add -L",
	)
	cmd.Env = agentEnv
	out, err = cmd.CombinedOutput()
	must.NoError(err, "ssh -A ssh-add -L: %s", out)
	is.NotEmpty(out, "ssh-add -L produced no output (agent not reachable)")
	t.Logf("agent key: %s", out)
}
