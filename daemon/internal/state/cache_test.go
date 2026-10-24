package state

import (
	"os"
	"slices"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/daemon/internal/paths"
)

func TestCacheRejectsInvalidPrincipals(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	c := NewCache()
	c.Replace(map[string][]string{
		"../../etc": {"uuid-1"},
		"0start":    {"uuid-1"},
		"":          {"uuid-1"},
	}, nil, "", "", nil, 0)

	is.Empty(c.CertPrincipals("../../etc"))
	is.Empty(c.CertPrincipals("0start"))
	is.Empty(c.CertPrincipals(""))
}

func TestCacheReplaceCopiesInput(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	c := NewCache()

	uuids := []string{"uuid-1", "uuid-2"}
	c.Replace(map[string][]string{"alice": uuids}, nil, "", "", nil, 0)
	uuids[0] = "mutated"

	is.Equal([]string{"uuid-1", "uuid-2"}, c.CertPrincipals("alice"))
}

func TestCacheCertPrincipalsReturnsCopy(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	c := NewCache()
	c.Replace(map[string][]string{"alice": {"uuid-1", "uuid-2"}}, nil, "", "", nil, 0)

	got := c.CertPrincipals("alice")
	got[0] = "mutated"

	is.True(slices.Contains(c.CertPrincipals("alice"), "uuid-1"))
	is.False(slices.Contains(c.CertPrincipals("alice"), "mutated"))
}

func TestCacheSaveLoadRoundTrip(t *testing.T) {
	newTestDataDir(t)
	is := assert.New(t)
	must := require.New(t)

	c := NewCache()
	c.Replace(map[string][]string{
		"alice": {"uuid-1", "uuid-2"},
		"bob":   {"uuid-3"},
	}, nil, "", "", nil, 0)
	must.NoError(c.Save())

	loaded := NewCache()
	must.NoError(loaded.Load())
	is.True(slices.Contains(loaded.CertPrincipals("alice"), "uuid-1"))
	is.True(slices.Contains(loaded.CertPrincipals("bob"), "uuid-3"))
}

func TestCacheLoadMissingFileIsNotAnError(t *testing.T) {
	newTestDataDir(t)
	is := assert.New(t)

	c := NewCache()
	is.NoError(c.Load())
}

func TestCacheDaemonConfigRoundTrip(t *testing.T) {
	newTestDataDir(t)
	is := assert.New(t)
	must := require.New(t)

	c := NewCache()
	record := true
	c.Replace(map[string][]string{"alice": {"uuid-1"}}, nil, "", "", nil, 0)
	c.SetDaemonConfig(&nokkuv1.DaemonConfig{
		RecordSessions: &record,
	})
	must.NoError(c.Save())

	loaded := NewCache()
	must.NoError(loaded.Load())
	is.True(loaded.DaemonConfig().GetRecordSessions())
	is.True(slices.Contains(loaded.CertPrincipals("alice"), "uuid-1"))
}

func TestCacheClearDropsSyncedConfig(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	record := true
	c := NewCache()
	c.SetDaemonConfig(&nokkuv1.DaemonConfig{RecordSessions: &record})
	is.True(c.DaemonConfig().GetRecordSessions())
	c.Clear()
	is.False(c.DaemonConfig().GetRecordSessions())
}

func TestCacheLoadIgnoresCorruptedFile(t *testing.T) {
	newTestDataDir(t)
	is := assert.New(t)
	must := require.New(t)

	c := NewCache()
	c.Replace(map[string][]string{"alice": {"uuid-1"}}, nil, "", "", nil, 0)
	must.NoError(c.Save())
	must.NoError(os.WriteFile(paths.CacheFile(), []byte("{not json"), 0o640))

	loaded := NewCache()
	must.NoError(loaded.Load())
	is.Empty(loaded.CertPrincipals("alice"))

	// The next save replaces the corrupt file.
	loaded.Replace(map[string][]string{"bob": {"uuid-2"}}, nil, "", "", nil, 0)
	must.NoError(loaded.Save())
	again := NewCache()
	must.NoError(again.Load())
	is.Equal([]string{"uuid-2"}, again.CertPrincipals("bob"))
}

func TestCacheClear(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	c := NewCache()
	c.Replace(map[string][]string{"alice": {"uuid-1"}}, nil, "", "", nil, 0)
	c.Clear()

	is.Empty(c.CertPrincipals("alice"))

	// Clearing must not leave a nil map behind. Subsequent writes must work.
	c.Replace(map[string][]string{"bob": {"uuid-2"}}, nil, "", "", nil, 0)
	is.Equal([]string{"uuid-2"}, c.CertPrincipals("bob"))
}

func TestCacheConcurrentAccess(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	c := NewCache()

	var wg sync.WaitGroup
	for i := range 4 {
		wg.Go(func() {
			for range 200 {
				principal := "user"
				if i%2 == 0 {
					principal = "user2"
				}
				c.Replace(map[string][]string{
					principal: {"uuid-1", "uuid-2"},
					"other":   {"uuid-3"},
				}, nil, "", "", nil, 0)
				_ = c.CertPrincipals(principal)
				_ = c.CertPrincipals("other")
			}
		})
	}
	wg.Wait()

	is.True(
		slices.Contains(c.CertPrincipals("user"), "uuid-1") ||
			slices.Contains(c.CertPrincipals("user2"), "uuid-1"),
	)
}

func TestCacheReplace(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	c := NewCache()

	// Pre-existing state must be fully replaced, not merged.
	c.Replace(map[string][]string{"stale": {"uuid-old"}}, nil, "", "", nil, 0)

	c.Replace(
		map[string][]string{
			"alice":     {"uuid-1", "uuid-2"},
			"../../etc": {"uuid-evil"}, // invalid, must be skipped
		},
		&nokkuv1.DaemonConfig{RecordSessions: new(true)},
		"ssh-ed25519 BBBB",
		"ssh-ed25519 HHHH",
		[]*nokkuv1.RetiredCAKey{{PublicKey: new("ssh-ed25519 AAAA")}},
		7,
	)
	active, retired := c.CAs()
	is.Equal("ssh-ed25519 BBBB", active)
	is.Equal("ssh-ed25519 HHHH", c.HostCA(), "the host CA is kept apart from the login CA")
	is.Len(retired, 1)

	is.Empty(c.CertPrincipals("stale"))
	is.Equal([]string{"uuid-1", "uuid-2"}, c.CertPrincipals("alice"))
	is.Empty(c.CertPrincipals("../../etc"))
	is.EqualValues(7, c.GetStateVersion())
	is.True(c.DaemonConfig().GetRecordSessions())

	// Replacing with an empty map must yield an empty map, not nil.
	c.Replace(nil, nil, "", "", nil, 0)
	is.NotNil(c.data.Principals)
}
