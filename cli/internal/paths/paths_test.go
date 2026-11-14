package paths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigPathIsUnderHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	assert.Equal(t, filepath.Join(home, ".config", "nk"), ConfigDir())
	require.NoError(t, EnsureDirs())
	fi, err := os.Stat(SSHCertDir())
	require.NoError(t, err)
	assert.True(t, fi.IsDir())
}

func TestEnsurePathsWithoutHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("home does not derive from HOME on windows")
	}
	t.Setenv("HOME", "")
	assert.Error(t, EnsureDirs(), "startup must stop when no home resolves")
}

func TestClearConfigDirKeepsOnlyTheSignerKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	require.NoError(t, EnsureDirs())
	for _, f := range []string{SignerStateFile(), ConfigFile(), SSHSignerFile(), SSHCertificate("a")} {
		require.NoError(t, os.WriteFile(f, []byte("x"), 0o600))
	}

	require.NoError(t, ClearConfigDir())

	left, err := os.ReadDir(ConfigDir())
	require.NoError(t, err)
	require.Len(t, left, 1, "a logout left more than the signer key")
	assert.Equal(t, "signer.json", left[0].Name())
	require.NoError(t, ClearConfigDir(), "a second logout")
}
