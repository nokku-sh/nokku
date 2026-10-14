package cmd

import (
	"context"
	"encoding/json"
	"slices"
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
	targets := slices.Concat(testState().Targets, []state.Target{
		{ID: "t-5", Name: "nat-a", Endpoints: []string{"1.2.3.4:2201"}},
		{ID: "t-6", Name: "nat-b", Endpoints: []string{"1.2.3.4:2202"}},
	})
	aliases := map[string]string{"t-1": "nokku/web"}

	tests := []struct {
		name   string
		dest   remote
		wantID string
		wantAt remote
		errMsg string
	}{
		{"by name, at its endpoint", remote{host: "web"}, "t-1", remote{host: "10.0.0.5", port: "2222"}, ""},
		{"by nk ls alias", remote{host: "nokku/web"}, "t-1", remote{host: "10.0.0.5", port: "2222"}, ""},
		{
			"--port beats the endpoint port",
			remote{host: "web", port: "22"},
			"t-1",
			remote{host: "10.0.0.5", port: "22"},
			"",
		},
		{"by host, at the stored port", remote{host: "10.0.0.5"}, "t-1", remote{host: "10.0.0.5", port: "2222"}, ""},
		{"by host and port", remote{host: "10.0.0.5", port: "2222"}, "t-1", remote{host: "10.0.0.5", port: "2222"}, ""},
		{
			"another port is another server",
			remote{host: "10.0.0.5", port: "22"},
			"",
			remote{host: "10.0.0.5", port: "22"},
			"",
		},
		{
			"no port on an endpoint means 22",
			remote{host: "10.0.0.7", port: "2222"},
			"",
			remote{host: "10.0.0.7", port: "2222"},
			"",
		},
		{"unknown host is a new target", remote{host: "10.0.0.9"}, "", remote{host: "10.0.0.9"}, ""},
		{"the name settles a shared endpoint", remote{host: "dup"}, "t-3", remote{host: "10.0.0.7"}, ""},
		{
			"the port settles a shared IP",
			remote{host: "1.2.3.4", port: "2202"},
			"t-6",
			remote{host: "1.2.3.4", port: "2202"},
			"",
		},
		{"a shared IP without a port", remote{host: "1.2.3.4"}, "", remote{}, "several targets"},
		{"a shared endpoint", remote{host: "10.0.0.7"}, "", remote{}, "several targets"},
		{"a daemon target", remote{host: "db"}, "", remote{}, "daemon"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, at, err := findTarget(targets, aliases, tt.dest)
			if tt.errMsg != "" {
				require.ErrorContains(t, err, tt.errMsg)
				return
			}
			require.NoError(t, err)
			if tt.wantID == "" {
				assert.Nil(t, got, "no target matches")
			} else {
				require.NotNil(t, got, "a target matches")
				assert.Equal(t, tt.wantID, got.ID)
			}
			assert.Equal(t, tt.wantAt, at, "where nk connects")
		})
	}
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

// urfave splits a slice flag at commas unless told not to, tearing one account's subjects apart.
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
