package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cryptossh "golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokku/cli/internal/paths"
	"github.com/nokku-sh/nokku/cli/internal/state"
)

// setupSSHDir points home at a temp dir so tests never touch real state.
func setupSSHDir(t *testing.T) {
	t.Helper()
	//nolint:usetesting // the t.TempDir path is too long for the agent socket on macOS
	home, err := os.MkdirTemp("", "nk")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	require.NoError(t, paths.EnsureDirs())
}

func setupKey(t *testing.T, requireTPM bool) {
	t.Helper()
	require.NoError(t, SetupKey(&state.State{RequireTPM: requireTPM}))
}

// securityKeyLine is the public half of an ed25519-sk key, x/crypto can't make one.
func securityKeyLine(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := cryptossh.ParsePublicKey(cryptossh.Marshal(struct {
		Name        string
		Key         []byte
		Application string
	}{cryptossh.KeyAlgoSKED25519, pub, "ssh:nokku"}))
	require.NoError(t, err)
	return strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(key)))
}

func TestSetupKeyIsStable(t *testing.T) {
	setupSSHDir(t)

	setupKey(t, false)
	pub, err := os.ReadFile(paths.PubKeyFile())
	require.NoError(t, err)

	setupKey(t, false)
	pub2, err := os.ReadFile(paths.PubKeyFile())
	require.NoError(t, err)
	assert.Equal(t, pub, pub2, "the identity must be stable across runs")

	key, err := PubKey()
	require.NoError(t, err)
	assert.Equal(t, strings.TrimSpace(string(pub)), key)
}

func TestSetupKeyChangedIdentityDropsCerts(t *testing.T) {
	setupSSHDir(t)
	cert := paths.SSHCertificate("0199a0a0-0000-7000-8000-000000000002")
	require.NoError(t, os.WriteFile(paths.PubKeyFile(), []byte("ssh-ed25519 AAAAstale x@nokku\n"), 0o600))
	require.NoError(t, os.WriteFile(cert, []byte("stale"), 0o600))

	setupKey(t, false)
	assert.NoFileExists(t, cert, "certificates for the old identity must be removed")
}

func TestSetupKeySecurityKey(t *testing.T) {
	setupSSHDir(t)
	s := &state.State{SecurityKey: true}

	require.ErrorContains(t, SetupKey(s), "nk login --security-key", "no handle file yet")

	sk := securityKeyLine(t)
	require.NoError(t, os.WriteFile(paths.SecurityKeyFile()+".pub", []byte(sk+" roxas@laptop\n"), 0o600))
	require.ErrorContains(t, SetupKey(s), "nk login --security-key", "the handle ssh_config points at is gone")

	require.NoError(t, os.WriteFile(paths.SecurityKeyFile(), []byte("handle"), 0o600))
	require.NoError(t, SetupKey(s))
	key, err := PubKey()
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(key, sk+" "), "nokku.pub holds the security key, got %q", key)
	assert.NoFileExists(t, paths.SSHSignerFile(), "a security key needs no TPM key")

	require.NoError(t, os.WriteFile(paths.SecurityKeyFile()+".pub", []byte("ssh-ed25519 "+
		"AAAAC3NzaC1lZDI1NTE5AAAAIFnqlkEEgnnAYIr5pXed65L5FfJ5iwFb/dx4g0LI+YJe x\n"), 0o600))
	require.ErrorContains(t, SetupKey(s), "ssh-ed25519 key", "a plain key in the handle's place")

	require.NoError(t, os.WriteFile(paths.SecurityKeyFile()+".pub", []byte(sk+" roxas@laptop\n"), 0o600))
	s.RequireTPM = true
	require.NoError(t, SetupKey(s), "--require-tpm refuses software keys only, a security key is hardware")
}
