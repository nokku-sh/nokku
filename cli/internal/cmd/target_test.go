package cmd

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nokku/cli/internal/client"
	"github.com/nokku-sh/nokku/cli/internal/manual"
	"github.com/nokku-sh/nokku/cli/internal/state"
)

func testState() *state.State {
	return &state.State{
		CAs: []state.CA{
			{ID: "ca-1", Name: "main", Default: true},
			{ID: "ca-2", Name: "legacy"},
		},
		Targets: []state.Target{
			{ID: "t-1", Name: "web", Endpoints: []string{"10.0.0.5:2222"}},
			{ID: "t-2", Name: "db", DaemonID: "d", Endpoints: []string{"10.0.0.6"}},
			{ID: "t-3", Name: "dup", Endpoints: []string{"10.0.0.7"}},
			{ID: "t-4", Name: "other", Endpoints: []string{"10.0.0.7"}},
		},
	}
}

func TestFindTarget(t *testing.T) {
	t.Parallel()
	s := testState()

	got, err := findTarget(s, "web")
	require.NoError(t, err)
	assert.Equal(t, "t-1", got.ID, "by name")

	got, err = findTarget(s, "10.0.0.5")
	require.NoError(t, err)
	assert.Equal(t, "t-1", got.ID, "by endpoint host, ignoring its port")

	got, err = findTarget(s, "10.0.0.9")
	require.NoError(t, err)
	assert.Nil(t, got, "an unknown host is a new target")

	_, err = findTarget(s, "db")
	require.ErrorContains(t, err, "daemon")

	_, err = findTarget(s, "10.0.0.7")
	require.ErrorContains(t, err, "several targets")
	got, err = findTarget(s, "dup")
	require.NoError(t, err)
	assert.Equal(t, "t-3", got.ID, "the name settles a shared endpoint")
}

func TestResolveCA(t *testing.T) {
	t.Parallel()
	cas := testState().CAs

	ca, err := resolveCA(cas, "")
	require.NoError(t, err)
	assert.Equal(t, "ca-1", ca.ID, "the default wins")

	ca, err = resolveCA(cas, "legacy")
	require.NoError(t, err)
	assert.Equal(t, "ca-2", ca.ID)

	_, err = resolveCA(cas, "nope")
	require.Error(t, err)

	ca, err = resolveCA(cas, "LEGACY")
	require.NoError(t, err)
	assert.Equal(t, "ca-2", ca.ID, "a name matches without its case")

	cas = append(cas, state.CA{ID: "ca-3", Name: "Legacy"})
	ca, err = resolveCA(cas, "Legacy")
	require.NoError(t, err)
	assert.Equal(t, "ca-3", ca.ID, "the exact name wins")
	_, err = resolveCA(cas, "LEGACY")
	require.ErrorContains(t, err, "pass the id", "two names that differ only by case")

	cas = append(cas, state.CA{ID: "ca-4", Name: "Legacy"})
	_, err = resolveCA(cas, "Legacy")
	require.ErrorContains(t, err, "pass the id", "two CAs with the same name")
	ca, err = resolveCA(cas, "ca-4")
	require.NoError(t, err)
	assert.Equal(t, "ca-4", ca.ID, "the id settles it")

	cas[0].Default = false
	_, err = resolveCA(cas, "")
	require.ErrorContains(t, err, "--ca")

	cas = cas[:1]
	ca, err = resolveCA(cas, "")
	require.NoError(t, err)
	assert.Equal(t, "ca-1", ca.ID, "the only CA needs no flag")
}

func TestEndpointRemote(t *testing.T) {
	t.Parallel()
	assert.Equal(t, remote{host: "10.0.0.5", port: "2222"}, endpointRemote("10.0.0.5:2222", ""))
	assert.Equal(t, remote{host: "10.0.0.5", port: "22"}, endpointRemote("10.0.0.5:2222", "22"))
	assert.Equal(t, remote{host: "web.lan"}, endpointRemote("web.lan", ""))
	assert.Equal(t, "ssh -p 2222 root@10.0.0.5", remote{host: "10.0.0.5", port: "2222"}.String())
	assert.Equal(t, "ssh root@web.lan", remote{host: "web.lan"}.String())
}

func TestSyncResultJSON(t *testing.T) {
	t.Parallel()
	target := &state.Target{Name: "web"}
	plan := manual.NewPlan(
		"ssh-ed25519 AAAA ca",
		map[string][]string{"root": {"user-1"}},
		manual.Host{Accounts: []string{"root"}, Principals: []string{"root", "gone"}},
	)

	for _, dryRun := range []bool{true, false} {
		b, err := json.Marshal(newSyncResult(target, plan, nil, dryRun))
		require.NoError(t, err)
		var got struct {
			Target string `json:"target"`
			DryRun bool   `json:"dry_run"`
			Files  []struct {
				Path    string `json:"path"`
				Content string `json:"content"`
			} `json:"files"`
			Removed []string `json:"removed"`
		}
		require.NoError(t, json.Unmarshal(b, &got))

		assert.Equal(t, "web", got.Target)
		assert.Equal(t, dryRun, got.DryRun)
		require.Len(t, got.Files, 3, "CA, drop-in, and one principals file")
		assert.Equal(t, "/etc/ssh/nokku_principals/root", got.Files[2].Path)
		assert.Equal(t, "user-1\n", got.Files[2].Content)
		assert.Equal(t, []string{"/etc/ssh/nokku_principals/gone"}, got.Removed)
	}

	b, err := json.Marshal(newSyncResult(target, manual.Plan{}, nil, false))
	require.NoError(t, err)
	assert.Contains(t, string(b), `"removed":[]`, "scripts get a list, never null")
	assert.NotContains(t, string(b), "grants", "only a new target that starts with grants names them")

	seeds := []client.Grant{{Account: "root", Subjects: []string{"me", "team:ops"}, Users: []string{"user-1"}}}
	b, err = json.Marshal(newSyncResult(target, manual.Plan{}, seeds, true))
	require.NoError(t, err)
	assert.Contains(t, string(b), `"grants":{"root":["me","team:ops"]}`, "as typed, ids stay out")
}

// urfave splits a slice flag at commas unless told otherwise, which would
// tear the subjects of one account apart.
func TestSyncKeepsTheSubjectsOfAGrantTogether(t *testing.T) {
	t.Parallel()
	var got []string
	sync := syncCMD()
	sync.Action = func(_ context.Context, cmd *cli.Command) error {
		got = cmd.StringSlice("grant")
		return nil
	}
	require.NoError(t, sync.Run(t.Context(), []string{"sync", "--grant", "root=me,team:ops", "10.0.0.5"}))
	assert.Equal(t, []string{"root=me,team:ops"}, got)
}

func TestCheckHostKey(t *testing.T) {
	assert.NoError(t, checkHostKey("", "ssh-ed25519 new", "web", false), "first sync pins the key")
	assert.NoError(t, checkHostKey("ssh-ed25519 old", "ssh-ed25519 old", "web", false))

	err := checkHostKey("ssh-ed25519 old", "ssh-ed25519 new", "web", false)
	require.Error(t, err, "a changed key stops the sync")
	assert.Contains(t, err.Error(), "--accept-host-key")

	assert.NoError(t, checkHostKey("ssh-ed25519 old", "ssh-ed25519 new", "web", true))
}

func TestPlainWriterDropsEscapeSequences(t *testing.T) {
	t.Parallel()
	var out strings.Builder
	in := []byte("sh: denied\x1b[2J\r\n\x1b]0;title\x07\u009b1A")
	n, err := plainWriter{&out}.Write(in)
	require.NoError(t, err)
	assert.Equal(t, len(in), n, "the whole input counts as written, or the copy stops")
	assert.Equal(t, "sh: denied[2J\n]0;title1A", out.String())
}
