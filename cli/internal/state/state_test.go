package state

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/cli/internal/paths"
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
	}
	require.NoError(t, s.Save())

	loaded := Load()
	assert.Equal(t, s.Config.APIURL, loaded.APIURL)
	assert.Equal(t, "sess", loaded.SessionToken)
	assert.True(t, loaded.SessionExpiresAt.Equal(expires))
	assert.Equal(t, s.Cache, loaded.Cache)
	assert.Empty(t, loaded.Token, "a token is never persisted")

	raw, err := os.ReadFile(paths.ConfigFile())
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "nk_sa_secret")
	fi, err := os.Stat(paths.ConfigFile())
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
}

// nk once kept a --ttl here. A file from then still loads.
func TestLoadTakesAConfigWithAFieldThatIsGone(t *testing.T) {
	setHome(t)
	old := `{"api_url":"https://a.example","session_token":"sess","ttl":3600000000000}`
	require.NoError(t, os.WriteFile(paths.ConfigFile(), []byte(old), 0o600))

	loaded := Load()
	assert.Equal(t, "https://a.example", loaded.APIURL)
	assert.Equal(t, "sess", loaded.SessionToken)
}

func TestSessionValid(t *testing.T) {
	t.Parallel()
	assert.False(t, (&State{}).SessionValid())
	assert.True(t, (&State{SessionToken: "tok"}).SessionValid(), "unknown expiry counts as valid")
	assert.True(t, (&State{SessionToken: "tok", SessionExpiresAt: time.Now().Add(time.Hour)}).SessionValid())
	assert.False(t, (&State{SessionToken: "tok", SessionExpiresAt: time.Now().Add(-time.Minute)}).SessionValid())
}

// A failed sync falls back to the disk, which may name another server by then.
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

// Only an nk login --ci session counts, not what NK_TOKEN left behind.
func TestCIJob(t *testing.T) {
	account := &ServiceAccount{ID: "sa", Name: "deploy"}
	tests := []struct {
		name  string
		state State
		want  bool
	}{
		{"a job's session", State{SessionToken: "s", ServiceAccount: account}, true},
		{
			"a job's session that expired",
			State{
				SessionToken: "s", SessionExpiresAt: time.Now().Add(-time.Hour),
				ServiceAccount: account,
			},
			true,
		},
		{"a snapshot NK_TOKEN left behind", State{ServiceAccount: account}, false},
		{"NK_TOKEN set", State{Token: "k", ServiceAccount: account}, false},
		{"a person", State{SessionToken: "s", User: &User{ID: "u"}}, false},
		{"nobody", State{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.state.CIJob())
		})
	}
}

func TestBehind(t *testing.T) {
	t.Parallel()
	now := time.Now()
	ca := CA{RotatedAt: now}
	assert.False(t, Target{}.Behind(CA{}), "a CA never rolled over leaves no server behind")
	assert.False(t, Target{}.Behind(ca), "a server never synced has no known key")
	assert.True(t, Target{LastSyncAt: now.Add(-time.Hour)}.Behind(ca), "synced before the rollover")
	assert.False(t, Target{LastSyncAt: now.Add(time.Minute)}.Behind(ca), "synced after it")
	assert.False(t, Target{DaemonID: "d", LastSyncAt: now.Add(-time.Hour)}.Behind(ca), "a daemon learns the key itself")
}
