package state

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/daemon/internal/paths"
)

func newTestDataDir(t *testing.T) {
	t.Helper()
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
}

func TestAccessFromDropsInvalidAccounts(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	a := AccessFrom(&nokkuv1.SyncDaemonResponse{
		Principals: []*nokkuv1.AccountPrincipals{
			{Username: new("alice"), CertPrincipals: []string{"uuid-1", "uuid-2"}},
			{Username: new("../../etc"), CertPrincipals: []string{"uuid-1"}},
			{Username: new("0start"), CertPrincipals: []string{"uuid-1"}},
			{Username: new(""), CertPrincipals: []string{"uuid-1"}},
		},
		CaPublicKey:     new("ssh-ed25519 BBBB"),
		HostCaPublicKey: new("ssh-ed25519 HHHH"),
		RetiredCaKeys:   []*nokkuv1.RetiredCAKey{{PublicKey: new("ssh-ed25519 AAAA")}},
		Config:          &nokkuv1.DaemonConfig{RecordSessions: new(true)},
		StateVersion:    new(int64(7)),
	})

	is.Equal(map[string][]string{"alice": {"uuid-1", "uuid-2"}}, a.Principals)
	is.Equal("ssh-ed25519 BBBB", a.CA)
	is.Equal("ssh-ed25519 HHHH", a.HostCA, "the host CA is kept apart from the login CA")
	is.Len(a.RetiredCAs, 1)
	is.True(a.DaemonConfig.GetRecordSessions())
	is.EqualValues(7, a.StateVersion)
}

// Enrollment and access share a file, so a restart sees both from one moment.
func TestSaveLoadRoundTrip(t *testing.T) {
	newTestDataDir(t)
	is := assert.New(t)
	must := require.New(t)

	until := time.Now().Add(time.Hour).Truncate(time.Second)
	s := New(Config{TargetID: "tgt-1", DaemonID: "daemon-1", APIURL: "https://api.example.com", SessionToken: "tok"})
	s.SetAccess(&Access{
		Principals:   map[string][]string{"alice": {"uuid-1", "uuid-2"}, "bob": {"uuid-3"}},
		DaemonConfig: &nokkuv1.DaemonConfig{RecordSessions: new(true)},
		CA:           "ssh-ed25519 BBBB",
		RetiredCAs: []*nokkuv1.RetiredCAKey{
			{PublicKey: new("ssh-ed25519 AAAA"), TrustedUntil: timestamppb.New(until)},
		},
		HostCA:       "ssh-ed25519 HHHH",
		StateVersion: 7,
	})
	must.NoError(s.Save())

	loaded, err := Load()
	must.NoError(err)
	is.Equal(s.Config, loaded.Config)
	a := loaded.Access()
	is.Equal(map[string][]string{"alice": {"uuid-1", "uuid-2"}, "bob": {"uuid-3"}}, a.Principals)
	is.True(a.DaemonConfig.GetRecordSessions())
	is.Equal("ssh-ed25519 BBBB", a.CA)
	is.Equal("ssh-ed25519 HHHH", a.HostCA)
	must.Len(a.RetiredCAs, 1)
	is.Equal("ssh-ed25519 AAAA", a.RetiredCAs[0].GetPublicKey())
	is.True(until.Equal(a.RetiredCAs[0].GetTrustedUntil().AsTime()))
	is.EqualValues(7, a.StateVersion)
	is.EqualValues(7, loaded.SavedVersion(), "the version on disk is the one to report")
}

func TestLoadMissingFileStartsEmpty(t *testing.T) {
	newTestDataDir(t)
	is := assert.New(t)

	s, err := Load()
	require.NoError(t, err)
	is.Empty(s.DaemonID)
	is.NotNil(s.Access())
	is.Empty(s.Access().Principals)
	is.Zero(s.SavedVersion())
}

// A hand-edited file cannot sneak in an unsafe account name.
func TestLoadDropsInvalidAccounts(t *testing.T) {
	newTestDataDir(t)
	must := require.New(t)
	must.NoError(os.WriteFile(paths.StateFile(), []byte(`{"access": {"principals": {
		"alice": ["uuid-1"], "../../etc": ["uuid-1"], "0start": ["uuid-1"]
	}}}`), 0o600))

	s, err := Load()
	must.NoError(err)
	assert.Equal(t, map[string][]string{"alice": {"uuid-1"}}, s.Access().Principals)
}

func TestLoadIgnoresCorruptedFile(t *testing.T) {
	newTestDataDir(t)
	is := assert.New(t)
	must := require.New(t)

	s := New(Config{TargetID: "tgt-1"})
	s.SetAccess(&Access{Principals: map[string][]string{"alice": {"uuid-1"}}})
	must.NoError(s.Save())
	must.NoError(os.WriteFile(paths.StateFile(), []byte("{not json"), 0o600))

	loaded, err := Load()
	must.NoError(err)
	is.Empty(loaded.TargetID)
	is.Empty(loaded.Access().Principals)

	// The next save replaces the corrupt file.
	loaded.TargetID = "tgt-2"
	loaded.SetAccess(&Access{Principals: map[string][]string{"bob": {"uuid-2"}}})
	must.NoError(loaded.Save())
	again, err := Load()
	must.NoError(err)
	is.Equal("tgt-2", again.TargetID)
	is.Equal([]string{"uuid-2"}, again.Access().Principals["bob"])
}

func TestSaveSkipsUnchanged(t *testing.T) {
	newTestDataDir(t)
	must := require.New(t)

	s := New(Config{TargetID: "tgt-1"})
	must.NoError(s.Save())
	fi, err := os.Stat(paths.StateFile())
	must.NoError(err)
	must.NoError(s.Save())
	fi2, err := os.Stat(paths.StateFile())
	must.NoError(err)
	assert.Equal(t, fi.ModTime(), fi2.ModTime())
}

// The file holds the session token.
func TestSaveWritesWithPrivatePerms(t *testing.T) {
	newTestDataDir(t)
	must := require.New(t)

	must.NoError(New(Config{TargetID: "tgt-1", SessionToken: "tok"}).Save())
	fi, err := os.Stat(paths.StateFile())
	must.NoError(err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
}

func TestStateFileNeverContainsPaths(t *testing.T) {
	newTestDataDir(t)
	must := require.New(t)

	must.NoError(New(Config{TargetID: "tgt-1"}).Save())
	data, err := os.ReadFile(paths.StateFile())
	must.NoError(err)

	assert.NotContains(t, string(data), os.Getenv("NOKKUD_DATA_DIR"))
}

// Logins and the heartbeat read while a sync swaps and saves.
func TestStateConcurrentAccess(t *testing.T) {
	newTestDataDir(t)
	s := New(Config{})

	var wg sync.WaitGroup
	var saveErr error
	wg.Go(func() {
		for i := range 50 {
			s.SetAccess(&Access{Principals: map[string][]string{"alice": {"uuid-1"}}, StateVersion: int64(i)})
			if saveErr = s.Save(); saveErr != nil {
				return
			}
		}
	})
	for range 3 {
		wg.Go(func() {
			for range 50 {
				_ = s.Access().Principals["alice"]
				_ = s.SavedVersion()
			}
		})
	}
	wg.Wait()
	require.NoError(t, saveErr)
	assert.EqualValues(t, 49, s.SavedVersion())
}

// An enroll during a run writes a new enrollment, the service must not undo it.
func TestSaveKeepsANewerEnrollment(t *testing.T) {
	newTestDataDir(t)
	first := New(Config{DaemonID: "daemon-a", SessionToken: "token-a"})
	require.NoError(t, first.Save())

	running, err := Load()
	require.NoError(t, err)
	enrolling, err := Load()
	require.NoError(t, err)
	enrolling.DaemonID, enrolling.SessionToken = "daemon-b", "token-b"
	require.NoError(t, enrolling.Save(), "the enroll writes over the enrollment it read")

	require.ErrorIs(t, running.Save(), errReplaced)
	require.ErrorIs(t, running.Dropped().Save(), errReplaced, "a rejection of the old one wiped the new one")
	onDisk, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "daemon-b", onDisk.DaemonID)
	assert.Equal(t, "token-b", onDisk.SessionToken)
}
