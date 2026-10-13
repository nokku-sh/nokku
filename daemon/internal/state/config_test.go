package state

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/daemon/internal/paths"
)

func newTestDataDir(t *testing.T) {
	t.Helper()
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
}

func TestConfigSaveLoadRoundTrip(t *testing.T) {
	newTestDataDir(t)
	is := assert.New(t)
	must := require.New(t)

	c := new(Config)
	c.TargetID = "tgt-1"
	c.DaemonID = "daemon-1"
	c.APIURL = "https://api.example.com"

	must.NoError(c.Save())

	loaded := new(Config)
	must.NoError(loaded.Load())
	is.Equal("tgt-1", loaded.TargetID)
	is.Equal("daemon-1", loaded.DaemonID)
	is.Equal("https://api.example.com", loaded.APIURL)
}

func TestConfigLoadMissingFileIsNotAnError(t *testing.T) {
	newTestDataDir(t)
	is := assert.New(t)

	c := new(Config)
	is.NoError(c.Load())
}

func TestConfigLoadIgnoresCorruptedFile(t *testing.T) {
	newTestDataDir(t)
	is := assert.New(t)
	must := require.New(t)

	c := new(Config)
	c.TargetID = "tgt-1"
	must.NoError(c.Save())
	must.NoError(os.WriteFile(paths.ConfigFile(), []byte("{not json"), 0o600))

	loaded := new(Config)
	must.NoError(loaded.Load())
	is.Empty(loaded.TargetID)

	// The next save replaces the corrupt file.
	loaded.TargetID = "tgt-2"
	must.NoError(loaded.Save())
	again := new(Config)
	must.NoError(again.Load())
	is.Equal("tgt-2", again.TargetID)
}

func TestConfigSaveSkipsUnchanged(t *testing.T) {
	newTestDataDir(t)
	is := assert.New(t)
	must := require.New(t)

	c := new(Config)
	c.TargetID = "tgt-1"
	must.NoError(c.Save())
	fi, err := os.Stat(paths.ConfigFile())
	must.NoError(err)
	is.NoError(c.Save())
	fi2, err := os.Stat(paths.ConfigFile())
	must.NoError(err)
	is.Equal(fi.ModTime(), fi2.ModTime())
}

func TestConfigSaveWritesWithPrivatePerms(t *testing.T) {
	newTestDataDir(t)
	is := assert.New(t)
	must := require.New(t)

	c := new(Config)
	c.TargetID = "tgt-1"
	must.NoError(c.Save())
	fi, err := os.Stat(paths.ConfigFile())
	must.NoError(err)
	is.Equal(os.FileMode(0o600), fi.Mode().Perm())
}

func TestConfigFileNeverContainsPaths(t *testing.T) {
	newTestDataDir(t)
	is := assert.New(t)
	must := require.New(t)

	dataDir := os.Getenv("NOKKUD_DATA_DIR")
	c := new(Config)
	c.TargetID = "tgt-1"
	must.NoError(c.Save())
	data, err := os.ReadFile(paths.ConfigFile())
	must.NoError(err)

	// The enrollment state is shared with the control plane, the data dir must not leak into it.
	is.NotContains(string(data), dataDir)
}
