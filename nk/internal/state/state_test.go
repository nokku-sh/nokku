package state

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/nk/internal/paths"
)

func setHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	require.NoError(t, paths.EnsureDirs())
}

func TestSaveLoadRoundTrip(t *testing.T) {
	setHome(t)
	expires := time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC)
	s := &State{
		APIURL: "https://a.example", SessionToken: "sess", SessionExpiresAt: expires,
		Targets: []Target{{ID: "t", Name: "web"}}, User: &User{ID: "u"},
		Token: "nk_sa_secret",
		TTL:   time.Hour,
	}
	require.NoError(t, s.Save())

	loaded := Load()
	assert.Equal(t, s.Config.APIURL, loaded.APIURL)
	assert.Equal(t, "sess", loaded.SessionToken)
	assert.True(t, loaded.SessionExpiresAt.Equal(expires))
	assert.Equal(t, s.Cache, loaded.Cache)
	assert.Zero(t, loaded.TTL, "flags are never persisted")

	raw, err := os.ReadFile(paths.ConfigFile())
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "nk_sa_secret")
	fi, err := os.Stat(paths.ConfigFile())
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
}

func TestSessionValid(t *testing.T) {
	t.Parallel()
	assert.False(t, (&State{}).SessionValid())
	assert.True(t, (&State{SessionToken: "tok"}).SessionValid(), "unknown expiry counts as valid")
	assert.True(t, (&State{SessionToken: "tok", SessionExpiresAt: time.Now().Add(time.Hour)}).SessionValid())
	assert.False(t, (&State{SessionToken: "tok", SessionExpiresAt: time.Now().Add(-time.Minute)}).SessionValid())
}

// The fallback after a failed sync reads the disk again, and by then the
// state may point at another server.
func TestLoadCacheLeavesOutAnotherServer(t *testing.T) {
	setHome(t)
	snapshot := Cache{Server: "https://a.example", Targets: []Target{{ID: "t", Name: "web"}}, User: &User{ID: "u"}}
	require.NoError(t, (&State{APIURL: "https://a.example", Cache: snapshot}).Save())

	same := &State{APIURL: "https://a.example"}
	require.NoError(t, same.LoadCache())
	assert.True(t, same.HasCachedData())

	other := &State{APIURL: "https://b.example"}
	require.NoError(t, other.LoadCache())
	assert.Empty(t, other.Targets, "server a's targets showed up under server b")

	snapshot.Server = ""
	require.NoError(t, (&State{APIURL: "https://a.example", Cache: snapshot}).Save())
	old := &State{APIURL: "https://a.example"}
	require.NoError(t, old.LoadCache())
	assert.True(t, old.HasCachedData(), "a snapshot from before the field existed keeps ssh working offline")
}
