package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/nokku-sh/nokku/internal/tpm"

	"github.com/nokku-sh/nokku/cli/internal/paths"
)

// nopCloser keeps the simulator owned by the test that created it.
type nopCloser struct{ transport.TPMCloser }

func (nopCloser) Close() error { return nil }

// e2eSigner uses the real TPM when there is one and the simulator otherwise.
func e2eSigner(t *testing.T) tpm.Signer {
	t.Helper()

	opts := tpm.SignerOptions{
		StatePath: filepath.Join(t.TempDir(), "ssh-signer.json"),
	}
	if err := tpm.Available(); err == nil {
		t.Log("using real TPM device")
	} else {
		sim, simErr := simulator.OpenSimulator()
		if simErr != nil {
			t.Skipf("no TPM device and simulator unavailable: %v", simErr)
		}
		t.Cleanup(func() { _ = sim.Close() })
		opts.OpenTPM = func() (transport.TPMCloser, error) { return nopCloser{sim}, nil }
		t.Log("using TPM simulator")
	}

	signer, err := tpm.NewSigner(opts)
	require.NoError(t, err, "NewSigner")
	t.Cleanup(func() { _ = signer.Close() })
	require.Equal(t, tpm.MethodTPM, signer.Method(), "interop needs a TPM-backed signer")
	return signer
}

// The TPM identity against a real sshd, the private key lives only in the TPM.
func TestAgentSSHDInterop(t *testing.T) {
	sshd, err := exec.LookPath("sshd")
	if err != nil {
		t.Skip("sshd not available")
	}
	current, err := user.Current()
	if err != nil || current.Username == "" {
		t.Skip("cannot determine current user")
	}

	key := e2eSigner(t)

	sshPub, err := cryptossh.NewPublicKey(key.Public())
	require.NoError(t, err, "public key")

	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	caSigner, err := cryptossh.NewSignerFromKey(caPriv)
	require.NoError(t, err)
	cert := &cryptossh.Certificate{
		Key:             sshPub,
		Serial:          1,
		CertType:        cryptossh.UserCert,
		KeyId:           "e2e",
		ValidPrincipals: []string{current.Username},
		ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
	}
	require.NoError(t, cert.SignCert(rand.Reader, caSigner), "sign certificate")

	dir := t.TempDir()
	pubFile := filepath.Join(dir, "nokku.pub")
	certFile := filepath.Join(dir, "nokku-cert.pub")
	sockFile := filepath.Join(dir, "agent.sock")
	require.NoError(t, os.WriteFile(pubFile, cryptossh.MarshalAuthorizedKey(sshPub), 0o600))
	require.NoError(t, os.WriteFile(certFile, cryptossh.MarshalAuthorizedKey(cert), 0o600))
	caFile := filepath.Join(dir, "ca.pub")
	require.NoError(t, os.WriteFile(
		caFile,
		cryptossh.MarshalAuthorizedKey(caSigner.PublicKey()),
		0o600,
	))

	// Serve the TPM key on the agent socket, as RunAgent does.
	lc := net.ListenConfig{}
	ln, err := lc.Listen(t.Context(), "unix", sockFile)
	require.NoError(t, err, "listen")
	defer func() { _ = ln.Close() }()
	ring := agent.NewKeyring()
	require.NoError(t, ring.Add(agent.AddedKey{PrivateKey: key, Comment: "nokku (tpm)"}), "agent add")
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = agent.ServeAgent(ring, conn)
			}()
		}
	}()

	port := startSSHD(t, sshd, dir, caFile)

	baseArgs := []string{
		"-p", port,
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "PubkeyAuthentication=yes",
		"-o", "PasswordAuthentication=no",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=" + filepath.Join(dir, "known_hosts"),
		"-o", "CertificateFile=" + certFile,
		"-o", "IdentityFile=" + pubFile, // the key lives in the agent
		"-o", "LogLevel=DEBUG1",
	}
	env := []string{"SSH_AUTH_SOCK="} // never leak the user's real agent

	out, err := sshCmd(env, append(baseArgs,
		"-o", "IdentityAgent="+sockFile,
		current.Username+"@127.0.0.1", "true",
	))
	require.NoError(t, err, "ssh with TPM agent failed:\n%s", out)

	// Without the agent no usable private key is on disk, so auth fails.
	out, err = sshCmd(env, append(baseArgs,
		"-o", "IdentityAgent=none",
		current.Username+"@127.0.0.1", "true",
	))
	assert.Error(t, err, "ssh without agent unexpectedly succeeded:\n%s", out)
}

// The software key against a real sshd, with the options nk writes.
func TestAgentSSHDInteropSoftwareKey(t *testing.T) {
	sshd, err := exec.LookPath("sshd")
	if err != nil {
		t.Skip("sshd not available")
	}
	current, err := user.Current()
	if err != nil || current.Username == "" {
		t.Skip("cannot determine current user")
	}

	setupSSHDir(t)

	// An unusable TPM forces the software path and spares the real device.
	soft, err := tpm.NewSigner(tpm.SignerOptions{
		StatePath: paths.SSHSignerFile(),
		OpenTPM: func() (transport.TPMCloser, error) {
			return nil, errors.New("no TPM in this test")
		},
	})
	require.NoError(t, err, "create software identity")
	require.Equal(t, tpm.MethodSoft, soft.Method(), "expected the software fallback")
	require.NoError(t, soft.Close())

	// SetupKey loads the soft state and never consults the TPM.
	require.NoError(t, SetupKey(false))

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- RunAgent(ctx, false) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	require.Eventually(t, func() bool { return agentAlive(ctx) }, 5*time.Second, 50*time.Millisecond)

	pubLine, err := os.ReadFile(paths.PubKeyFile())
	require.NoError(t, err, "read public key")
	pub, _, _, _, err := cryptossh.ParseAuthorizedKey(pubLine)
	require.NoError(t, err, "parse public key")

	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	caSigner, err := cryptossh.NewSignerFromKey(caPriv)
	require.NoError(t, err)
	cert := &cryptossh.Certificate{
		Key:             pub,
		Serial:          1,
		CertType:        cryptossh.UserCert,
		KeyId:           "e2e-soft",
		ValidPrincipals: []string{current.Username},
		ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
	}
	require.NoError(t, cert.SignCert(rand.Reader, caSigner), "sign certificate")

	dir := t.TempDir()
	certFile := filepath.Join(dir, "nokku-cert.pub")
	caFile := filepath.Join(dir, "ca.pub")
	require.NoError(t, os.WriteFile(certFile, cryptossh.MarshalAuthorizedKey(cert), 0o600))
	require.NoError(t, os.WriteFile(caFile, cryptossh.MarshalAuthorizedKey(caSigner.PublicKey()), 0o600))

	port := startSSHD(t, sshd, dir, caFile)

	out, err := sshCmd([]string{"SSH_AUTH_SOCK="}, []string{
		"-p", port,
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "PubkeyAuthentication=yes",
		"-o", "PasswordAuthentication=no",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=" + filepath.Join(dir, "known_hosts"),
		"-o", "CertificateFile=" + certFile,
		"-o", "IdentityFile=" + paths.PubKeyFile(),
		"-o", "IdentityAgent=" + paths.AgentSocket(),
		"-o", "LogLevel=DEBUG1",
		current.Username + "@127.0.0.1", "true",
	})
	require.NoError(t, err, "ssh with the machine-wrapped software key failed:\n%s", out)
}

func sshCmd(env, args []string) (string, error) {
	// A host ssh config, like a ControlMaster, would change what this proves.
	cmd := exec.Command("ssh", append([]string{"-F", "/dev/null"}, args...)...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// startSSHD launches a same-user sshd trusting the test CA, returns its port.
func startSSHD(t *testing.T, sshd, dir, caFile string) string {
	t.Helper()

	hostKey := filepath.Join(dir, "host_key")
	keygen := exec.Command("ssh-keygen", "-t", "ed25519", "-f", hostKey, "-N", "", "-q")
	out, err := keygen.CombinedOutput()
	require.NoError(t, err, "ssh-keygen: %s", out)

	portLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := strconv.Itoa(portLn.Addr().(*net.TCPAddr).Port)
	require.NoError(t, portLn.Close())

	cfg := filepath.Join(dir, "sshd_config")
	config := fmt.Sprintf(`Port %s
ListenAddress 127.0.0.1
HostKey %s
PidFile %s
UsePAM no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile none
TrustedUserCAKeys %s
StrictModes no
`, port, hostKey, filepath.Join(dir, "sshd.pid"), caFile)
	require.NoError(t, os.WriteFile(cfg, []byte(config), 0o600))

	cmd := exec.Command(sshd, "-f", cfg, "-D", "-e")
	logFile, err := os.Create(filepath.Join(dir, "sshd.log"))
	require.NoError(t, err)
	cmd.Stderr = logFile
	require.NoError(t, cmd.Start(), "start sshd")
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = logFile.Close()
	})

	started := assert.Eventually(t, func() bool {
		conn, dialErr := net.DialTimeout("tcp", "127.0.0.1:"+port, 100*time.Millisecond)
		if dialErr != nil {
			return false
		}
		_ = conn.Close()
		return true
	}, 10*time.Second, 100*time.Millisecond)
	// Read after the wait, sshd has written nothing before it.
	sshdLog, _ := os.ReadFile(logFile.Name())
	require.True(t, started, "sshd did not start, log:\n%s", sshdLog)
	return port
}

func TestAgentSignOnlyAndShutdown(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("named pipe agent")
	}
	must := require.New(t)
	setupSSHDir(t)
	must.NoError(SetupKey(false))

	done := make(chan error, 1)
	go func() { done <- RunAgent(t.Context(), false) }()
	must.Eventually(func() bool { return agentAlive(t.Context()) }, 5*time.Second, 20*time.Millisecond)

	conn, err := dialAgent(t.Context())
	must.NoError(err)
	defer conn.Close()
	client := agent.NewClient(conn)
	keys, err := client.List()
	must.NoError(err)
	must.Len(keys, 1, "the agent serves exactly the Nokku identity")

	_, extra, err := ed25519.GenerateKey(rand.Reader)
	must.NoError(err)
	must.Error(client.Add(agent.AddedKey{PrivateKey: extra}), "ssh-add must not load keys into nk's agent")
	must.Error(client.RemoveAll(), "ssh-add -D must not empty nk's agent")
	must.Error(client.Lock([]byte("x")), "ssh-add -x must not lock nk's agent")

	StopAgent(t.Context())
	select {
	case err = <-done:
		must.NoError(err)
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not stop on the shutdown extension")
	}
}

// Two agents must not both listen, the loser would remove the winner's socket.
func TestAgentSocketHasOneOwner(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("named pipes are exclusive already")
	}
	must := require.New(t)
	setupSSHDir(t)

	first, err := listenAgent(t.Context())
	must.NoError(err)

	_, err = listenAgent(t.Context())
	must.Error(err, "a second agent took over a live socket")
	conn, err := dialAgent(t.Context())
	must.NoError(err, "the first agent's socket is gone")
	_ = conn.Close()

	must.NoError(first.Close())
	again, err := listenAgent(t.Context())
	must.NoError(err, "the socket stayed locked after its owner left")
	_ = again.Close()
}

// The agent lives for half an hour past its last use, also after a CI step.
func TestAgentEnvLeavesOutTheToken(t *testing.T) {
	t.Setenv("NK_TOKEN", "nk_sa_secret")
	t.Setenv("NK_REQUIRE_TPM", "1")

	env := agentEnv()
	assert.NotContains(t, strings.Join(env, "\n"), "nk_sa_secret")
	assert.Contains(t, env, "NK_REQUIRE_TPM=1", "everything else is passed on")
}
