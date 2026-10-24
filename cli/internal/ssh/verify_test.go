package ssh

import (
	"crypto/rand"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokku/cli/internal/paths"
	"github.com/nokku-sh/nokku/cli/internal/state"
)

const verifyTargetID = "0199a0a0-0000-7000-8000-000000000002"

// sshServer accepts key exchanges with hostKey and never lets anyone log in.
func sshServer(t *testing.T, hostKey ssh.Signer) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
		return nil, errors.New("denied")
	}}
	cfg.AddHostKey(hostKey)
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() {
				_, _, _, _ = ssh.NewServerConn(conn, cfg)
				_ = conn.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

func hostCertSigner(t *testing.T, ca ssh.Signer, principal string) ssh.Signer {
	t.Helper()
	host := newSigner(t)
	cert := &ssh.Certificate{
		Key:             host.PublicKey(),
		CertType:        ssh.HostCert,
		ValidPrincipals: []string{principal},
		ValidAfter:      uint64(time.Now().Add(-time.Hour).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
	}
	require.NoError(t, cert.SignCert(rand.Reader, ca))
	signer, err := ssh.NewCertSigner(cert, host)
	require.NoError(t, err)
	return signer
}

// trust writes the known_hosts a sync of s would write.
func trust(t *testing.T, s *state.State) {
	t.Helper()
	require.NoError(t, os.WriteFile(paths.KnownHostsFile(), renderKnownHosts(s), 0o600))
}

func TestVerifyHostDaemon(t *testing.T) {
	setupSSHDir(t)
	caSigner := newSigner(t)
	target := state.Target{ID: verifyTargetID, Name: "prod", DaemonID: "d", CAID: "ca"}
	trust(t, &state.State{
		CAs:     []state.CA{{ID: "ca", HostPublicKey: string(ssh.MarshalAuthorizedKey(caSigner.PublicKey()))}},
		Targets: []state.Target{target},
	})

	addr := sshServer(t, hostCertSigner(t, caSigner, verifyTargetID))
	require.NoError(t, verifyHost(t.Context(), addr, &target), "the target's own host certificate")

	addr = sshServer(t, hostCertSigner(t, newSigner(t), verifyTargetID))
	require.ErrorContains(t, verifyHost(t.Context(), addr, &target), "does not match", "another CA")

	addr = sshServer(t, hostCertSigner(t, caSigner, "0199a0a0-0000-7000-8000-000000000009"))
	require.ErrorContains(t, verifyHost(t.Context(), addr, &target), "does not match", "another target")

	addr = sshServer(t, newSigner(t))
	require.Error(t, verifyHost(t.Context(), addr, &target), "a plain host key, like the user's NAS")
}

func TestVerifyHostManual(t *testing.T) {
	setupSSHDir(t)
	host := newSigner(t)
	addr := sshServer(t, host)
	target := state.Target{
		ID: verifyTargetID, Name: "web", HostPublicKey: string(ssh.MarshalAuthorizedKey(host.PublicKey())),
	}

	trust(t, &state.State{Targets: []state.Target{target}})
	require.NoError(t, verifyHost(t.Context(), addr, &target))

	other := target
	other.HostPublicKey = string(ssh.MarshalAuthorizedKey(newSigner(t).PublicKey()))
	trust(t, &state.State{Targets: []state.Target{other}})
	require.ErrorContains(t, verifyHost(t.Context(), addr, &other), "does not match")
}

func TestNeedsVerify(t *testing.T) {
	t.Parallel()
	daemon := &state.Target{DaemonID: "d", Endpoints: []string{"10.0.0.5"}}
	assert.True(t, needsVerify(daemon, "10.0.0.5:22"), "the relay is the way out")
	assert.False(t, needsVerify(daemon, "203.0.113.9:22"), "a public address names one machine")

	single := &state.Target{Endpoints: []string{"10.0.0.5"}}
	assert.False(t, needsVerify(single, "10.0.0.5:22"), "nothing to fall back to, ssh checks the key itself")
	several := &state.Target{Endpoints: []string{"10.0.0.5", "203.0.113.9"}}
	assert.True(t, needsVerify(several, "10.0.0.5:22"))
}

func TestPrivateAddr(t *testing.T) {
	t.Parallel()
	for addr, want := range map[string]bool{
		"192.168.1.10:22":      true,
		"10.0.0.5:2222":        true,
		"172.16.3.4:22":        true,
		"100.100.1.2:22":       true,
		"169.254.1.1:22":       true,
		"[fd00::1]:22":         true,
		"[fe80::1]:22":         true,
		"203.0.113.9:22":       false,
		"127.0.0.1:22":         false,
		"host.example:22":      false,
		"[::ffff:10.0.0.1]:22": true,
		"10.0.0.5":             false,
	} {
		assert.Equal(t, want, privateAddr(addr), addr)
	}
}

// pinnedSSH runs the real ssh against addr with opts and returns what it printed. Login always fails, the server
// lets nobody in, so the output tells a refused host key from a refused login.
func pinnedSSH(t *testing.T, addr string, opts []string) string {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	args := []string{
		"-F", "/dev/null", "-p", port,
		"-o", "BatchMode=yes", "-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes",
	}
	args = append(args, opts...)
	out, _ := exec.CommandContext(t.Context(), "ssh", append(args, "--", host, "true")...).CombinedOutput()
	return string(out)
}

func TestPinnedHostOptions(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh not available")
	}
	host := newSigner(t)
	addr := sshServer(t, host)
	pin := func(key ssh.PublicKey) []string {
		target := &state.Target{
			ID: verifyTargetID, Name: "web", HostPublicKey: string(ssh.MarshalAuthorizedKey(key)),
		}
		opts, err := PinnedHostOptions(target, filepath.Join(t.TempDir(), "known_hosts"))
		require.NoError(t, err)
		return opts
	}

	out := pinnedSSH(t, addr, pin(host.PublicKey()))
	assert.NotContains(t, out, "Host key verification failed", out)
	assert.Contains(t, out, "Permission denied", "the pinned host gets as far as the login")

	out = pinnedSSH(t, addr, pin(newSigner(t).PublicKey()))
	assert.Contains(t, out, "Host key verification failed", "an impostor is refused before any login")
}

func TestPinnedHostOptionsRefusesAnUnusableKey(t *testing.T) {
	t.Parallel()
	target := &state.Target{ID: verifyTargetID, Name: "web", HostPublicKey: "ssh-ed25519 AAAA\nbad"}
	_, err := PinnedHostOptions(target, filepath.Join(t.TempDir(), "known_hosts"))
	require.Error(t, err)
}

func TestAcceptHostOptions(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh not available")
	}
	host := newSigner(t)
	addr := sshServer(t, host)
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")

	out := pinnedSSH(t, addr, AcceptHostOptions(&state.Target{ID: verifyTargetID}, knownHosts))
	assert.Contains(t, out, "Permission denied", out)
	written, err := os.ReadFile(knownHosts)
	require.NoError(t, err)
	assert.Contains(t, string(written), verifyTargetID+" ", "the key is stored under the target id")
}
