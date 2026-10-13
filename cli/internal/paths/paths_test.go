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
