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

func TestFindTarget(t *testing.T) {
	t.Parallel()
	targets := []state.Target{
		{ID: "t-1", Name: "web", Endpoints: []string{"10.0.0.5:2222"}},
		{ID: "t-2", Name: "db", DaemonID: "d", Endpoints: []string{"10.0.0.6"}},
		{ID: "t-3", Name: "dup", Endpoints: []string{"10.0.0.7"}},
		{ID: "t-4", Name: "other", Endpoints: []string{"10.0.0.7"}},
		{ID: "t-5", Name: "nat-a", Endpoints: []string{"1.2.3.4:2201"}},
		{ID: "t-6", Name: "nat-b", Endpoints: []string{"1.2.3.4:2202"}},
	}
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
	plan, err := manual.NewPlan("ssh-ed25519 AAAA ca", "0199a0a0-0000-7000-8000-000000000002")
	require.NoError(t, err)

	var b []byte
	for _, dryRun := range []bool{true, false} {
		b, err = json.Marshal(newSyncResult(target, plan, nil, dryRun))
		require.NoError(t, err)
		var got struct {
			Target string `json:"target"`
			DryRun bool   `json:"dry_run"`
			Files  []struct {
				Path    string `json:"path"`
				Content string `json:"content"`
			} `json:"files"`
		}
		require.NoError(t, json.Unmarshal(b, &got))

		assert.Equal(t, "web", got.Target)
		assert.Equal(t, dryRun, got.DryRun)
		require.Len(t, got.Files, 2, "the CA and the drop-in")
		assert.Equal(t, "/etc/ssh/nokku_ca.pub", got.Files[0].Path)
		assert.Equal(t, "/etc/ssh/sshd_config.d/60-nokku.conf", got.Files[1].Path)
	}

	b, err = json.Marshal(newSyncResult(target, plan, nil, false))
	require.NoError(t, err)
	assert.NotContains(t, string(b), "grants", "only a new target that starts with grants names them")

	seeds := []client.Grant{{Account: "root", Subjects: []string{"me", "team:ops"}, Users: []string{"user-1"}}}
	b, err = json.Marshal(newSyncResult(target, plan, seeds, true))
	require.NoError(t, err)
	assert.Contains(t, string(b), `"grants":{"root":["me","team:ops"]}`, "as typed, ids stay out")
}

func TestWithCreator(t *testing.T) {
	t.Parallel()
	person := &state.State{User: &state.User{ID: "me-id"}}
	ops := client.Grant{Account: "deploy", Subjects: []string{"team:ops"}, Teams: []string{"ops-id"}}
	tests := []struct {
		name  string
		as    *state.State
		seeds []client.Grant
		want  []client.Grant
	}{
		{
			"no grants",
			person,
			nil,
			[]client.Grant{{Account: "root", Subjects: []string{"me"}, Users: []string{"me-id"}}},
		},
		{
			"grants for others only",
			person,
			[]client.Grant{ops},
			[]client.Grant{ops, {Account: "root", Subjects: []string{"me"}, Users: []string{"me-id"}}},
		},
		{
			"root for others only",
			person,
			[]client.Grant{{Account: "root", Subjects: []string{"team:ops"}, Teams: []string{"ops-id"}}},
			[]client.Grant{{
				Account: "root", Subjects: []string{"team:ops", "me"},
				Users: []string{"me-id"}, Teams: []string{"ops-id"},
			}},
		},
		{
			"named by email on another account",
			person,
			[]client.Grant{{Account: "deploy", Subjects: []string{"me@example.com"}, Users: []string{"me-id"}}},
			[]client.Grant{{Account: "deploy", Subjects: []string{"me@example.com"}, Users: []string{"me-id"}}},
		},
		{
			"a service account",
			&state.State{ServiceAccount: &state.ServiceAccount{ID: "sa-id"}},
			[]client.Grant{ops},
			[]client.Grant{ops},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, withCreator(tt.seeds, tt.as))
		})
	}
}

// urfave splits slice flags at commas unless told, tearing a grant apart.
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

func TestCanRepin(t *testing.T) {
	t.Parallel()
	me := &state.State{User: &state.User{ID: "me-id"}}
	pinned := func(by string) *state.Target {
		return &state.Target{ID: "t1", Name: "web", HostPublicKey: "ssh-ed25519 old", CreatedBy: by}
	}
	require.NoError(t, canRepin(me, pinned("me-id")), "whoever added the server pins its new key")
	require.NoError(t, canRepin(me, &state.Target{Name: "web"}), "a new server has no key to replace")
	require.NoError(
		t,
		canRepin(me, &state.Target{ID: "t1", CreatedBy: "other-id"}),
		"a forgotten key is pinned by anyone",
	)

	err := canRepin(me, pinned("other-id"))
	require.Error(t, err, "someone else's server took a new host key")
	assert.Contains(t, err.Error(), "web app")
	require.Error(t, canRepin(me, pinned("")), "a server nobody is known to have added took a new host key")
}

func TestMachineOwns(t *testing.T) {
	t.Parallel()
	machine := &state.State{ServiceAccount: &state.ServiceAccount{ID: "sa-id"}}
	require.NoError(t, machineOwns(machine, &state.Target{CreatedBy: "sa-id"}))
	require.Error(t, machineOwns(machine, &state.Target{Name: "web", CreatedBy: "other-id"}))
	require.Error(t, machineOwns(machine, &state.Target{Name: "web"}), "a server nobody is known to have added")

	require.NoError(t, machineOwns(&state.State{User: &state.User{ID: "me-id"}}, &state.Target{CreatedBy: "other-id"}))
	fresh := &state.State{ServiceAccount: &state.ServiceAccount{Name: "ci"}}
	require.NoError(t, machineOwns(fresh, &state.Target{CreatedBy: "other-id"}), "the core decides for an unknown id")
}

func TestSomeoneElses(t *testing.T) {
	t.Parallel()
	me := &state.State{User: &state.User{ID: "me-id"}}
	assert.False(t, someoneElses(me, &state.Target{CreatedBy: "me-id"}))
	assert.True(t, someoneElses(me, &state.Target{CreatedBy: "other-id"}))
	assert.True(t, someoneElses(me, &state.Target{}), "a server nobody is known to have added is not mine")

	// The core holds these to their own servers and says why.
	machine := &state.State{ServiceAccount: &state.ServiceAccount{ID: "sa-id"}}
	assert.False(t, someoneElses(machine, &state.Target{CreatedBy: "other-id"}))
	assert.False(t, someoneElses(&state.State{}, &state.Target{CreatedBy: "other-id"}))
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

func TestSyncStaleTakesNoServer(t *testing.T) {
	for _, args := range [][]string{{"web-1"}, {"--name", "web"}, {"--port", "2222"}} {
		err := Root().Run(t.Context(), append([]string{"nk", "sync", "--stale"}, args...))
		assert.ErrorContains(t, err, "--stale picks the servers itself", "args %v", args)
	}
}
