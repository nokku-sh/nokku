package ssh

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mizuchilabs/kata/fsutil"

	"github.com/nokku-sh/nokku/nk/internal/paths"
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

func TestSetupKeyIsStable(t *testing.T) {
	setupSSHDir(t)

	require.NoError(t, SetupKey(false))
	pub, err := os.ReadFile(paths.PubKeyFile())
	require.NoError(t, err)

	require.NoError(t, SetupKey(false))
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
	require.NoError(t, fsutil.WriteFile(paths.PubKeyFile(), []byte("ssh-ed25519 AAAAstale x@nokku\n"), 0o600))
	require.NoError(t, fsutil.WriteFile(cert, []byte("stale"), 0o600))

	require.NoError(t, SetupKey(false))
	assert.False(t, fsutil.FileExists(cert), "certificates for the old identity must be removed")
}
