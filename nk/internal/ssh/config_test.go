package ssh

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/nk/internal/paths"
	"github.com/nokku-sh/nokku/nk/internal/state"
)

func TestRenderSSHConfig(t *testing.T) {
	setupSSHDir(t)
	st := &state.State{
		Targets: []state.Target{
			{ID: "t-1", Name: "web", CAID: "ca-1", Usernames: []string{"alice", "bob"}},
			{ID: "t-2", Name: "db", CAID: "ca-1", Usernames: []string{"alice"}},
			{ID: "t-3", Name: "DB", CAID: "ca-1", Usernames: []string{"alice"}},
			{ID: "t-4", Name: "no-users", CAID: "ca-1"},
			{ID: "t-5", Name: "prod\n    ProxyCommand curl evil", CAID: "ca-1", Usernames: []string{"a"}},
			{ID: "t-6", Name: "ok", CAID: "ca-1", Usernames: []string{"a\n    ProxyCommand curl evil"}},
			{ID: "t-7", Name: "a/b", CAID: "ca-1", Usernames: []string{"a"}},
			{ID: "t-8", Name: "github.com", CAID: "ca-1", Usernames: []string{"git"}},
			{ID: "t-9", Name: "10.0.0.5", CAID: "ca-1", Usernames: []string{"root"}},
			{ID: "t-10", Name: "wild", CAID: "ca-1", Usernames: []string{"*"}},
		},
	}
	out := string(renderSSHConfig(st, hostAliases(st, nil), "nk"))

	for _, want := range []string{
		"Match originalhost web exec \"nk prepare t-1\"\n\nHost web\n    User alice\n    ProxyCommand nk proxy t-1 %p\n    HostKeyAlias t-1\n",
		"    CertificateFile " + configValue(paths.SSHCertificate("t-1")) + "\n",
		"    IdentityAgent " + configValue(paths.AgentSocket()) + "\n",
		"Host nokku/t-2\n", // names that differ only by case fall back to the id
		"Host nokku/t-3\n",
	} {
		assert.Contains(t, out, want)
	}
	// A server names its own targets only. It never claims a real host.
	for _, forbidden := range []string{
		"no-users", "curl evil", "a/b", "\nHost db\n", "github.com", "10.0.0.5", "wild",
	} {
		assert.NotContains(t, out, forbidden)
	}
}

func TestConfigValueQuotesPaths(t *testing.T) {
	t.Parallel()
	assert.Equal(t, `"/Users/Jane Doe/.config/nk/ssh_config"`, configValue("/Users/Jane Doe/.config/nk/ssh_config"))
	assert.Equal(t, `"C:\\Users\\Jane Doe\\x"`, configValue(`C:\Users\Jane Doe\x`))
	assert.Equal(t, `"\\\\.\\pipe\\nk-agent"`, configValue(`\\.\pipe\nk-agent`))
	assert.Equal(t, `"\"C:\\Program Files\\nk.exe\" prepare t-1"`, configValue(`"C:\Program Files\nk.exe" prepare t-1`))
}

func TestRenderKnownHosts(t *testing.T) {
	t.Parallel()
	st := &state.State{
		CAs: []state.CA{
			{
				ID: "ca-1", PublicKey: "ssh-ed25519 AAAACa1== production",
				PreviousPublicKey: "ssh-ed25519 AAAAOld1==", PreviousTrustedUntil: time.Now().Add(time.Hour),
			},
			{
				ID: "ca-3", PublicKey: "ssh-ed25519 AAAACa3==",
				PreviousPublicKey: "ssh-ed25519 AAAAOld3==", PreviousTrustedUntil: time.Now().Add(-time.Hour),
			},
			{ID: "ca-2", PublicKey: "ssh-ed25519 AAAA==\nHost *\n    ProxyCommand curl evil"},
		},
		Targets: []state.Target{
			{ID: "t-1", CAID: "ca-1", DaemonID: "d-1"},
			{ID: "t-2", CAID: "ca-2", DaemonID: "d-2"},
			{ID: "t-3", CAID: "ca-1", HostPublicKey: "ssh-ed25519 AAAAhost== host"},
			{ID: "t-4", CAID: "ca-1"},
			{ID: "t-5", CAID: "ca-1", DaemonID: "d-5", HostPublicKey: "ssh-ed25519 AAAAstray"},
			{ID: "t-6", CAID: "ca-3", DaemonID: "d-6"},
		},
	}
	out := string(renderKnownHosts(st))

	assert.Contains(t, out, "@cert-authority t-1 ssh-ed25519 AAAACa1== production\n")
	assert.Contains(
		t,
		out,
		"@cert-authority t-1 ssh-ed25519 AAAAOld1==\n",
		"a replaced key stays trusted until its deadline",
	)
	assert.Contains(t, out, "@cert-authority t-6 ssh-ed25519 AAAACa3==\n")
	assert.NotContains(t, out, "AAAAOld3", "a replaced key past its deadline is dropped")
	assert.Contains(t, out, "t-3 ssh-ed25519 AAAAhost== host\n")
	assert.NotContains(t, out, "@cert-authority t-3", "manual targets are pinned, not CA trusted")
	assert.NotContains(t, out, "t-4", "nothing to pin without a host key")
	assert.NotContains(t, out, "AAAAstray", "daemon targets are never pinned by a raw key")
	assert.NotContains(t, out, "curl evil")
}

func TestInclude(t *testing.T) {
	setupSSHDir(t)
	cfg := paths.SSHUserConfig()

	require.NoError(t, ensureInclude(), "a missing ~/.ssh/config is created")
	data, err := os.ReadFile(cfg)
	require.NoError(t, err)
	assert.True(t, HasInclude(data))

	original := "Host own\n    HostName example.com\n"
	require.NoError(t, os.WriteFile(cfg, []byte(original), 0o600))
	require.NoError(t, ensureInclude())
	require.NoError(t, ensureInclude())
	data, err = os.ReadFile(cfg)
	require.NoError(t, err)
	assert.Equal(t, includeLine()+"\n\n"+original, string(data), "include goes on top, once")

	require.NoError(t, RemoveInclude())
	data, err = os.ReadFile(cfg)
	require.NoError(t, err)
	assert.Equal(t, original, string(data))
}

func TestIncludeKeepsSymlink(t *testing.T) {
	setupSSHDir(t)
	target := filepath.Join(t.TempDir(), "dotfiles-ssh-config")
	require.NoError(t, os.WriteFile(target, []byte("Host own\n"), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Dir(paths.SSHUserConfig()), 0o700))
	if err := os.Symlink(target, paths.SSHUserConfig()); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	require.NoError(t, ensureInclude())
	fi, err := os.Lstat(paths.SSHUserConfig())
	require.NoError(t, err)
	assert.NotZero(t, fi.Mode()&os.ModeSymlink, "the dotfile link must survive")
	data, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.True(t, HasInclude(data))
}

func TestNKCommandIsAbsolute(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows paths fall back to a PATH lookup")
	}
	self, err := os.Executable()
	require.NoError(t, err)
	assert.Equal(t, self, nkCommand(), "ProxyCommand must name this binary")
}

func writtenConfig(t *testing.T, st *state.State) string {
	t.Helper()
	require.NoError(t, WriteConfigs(st))
	out, err := os.ReadFile(paths.SSHConfigFile())
	require.NoError(t, err)
	return string(out)
}

// nk's Include sits on top of ~/.ssh/config, so its Host block would win. A
// name the user already sends somewhere stays theirs, whoever names a server
// like it.
func TestOwnSSHConfigKeepsItsNames(t *testing.T) {
	setupSSHDir(t)
	sshDir := filepath.Dir(paths.SSHUserConfig())
	require.NoError(t, os.MkdirAll(filepath.Join(sshDir, "conf.d", "a-directory"), 0o700))
	require.NoError(t, os.WriteFile(paths.SSHUserConfig(), []byte(`# mine
Include conf.d/* ~/.ssh/extra missing

Host *
    ProxyCommand none
    ForwardAgent no

Host bastion jump   # two names
    HostName 203.0.113.7
    ForwardAgent yes

Host web
    LocalForward 8080 localhost:80
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(sshDir, "conf.d", "work"), []byte(`
host=prod-* !prod-open
  proxyjump jump

Match originalhost gitbox,mirror user git
  Hostname git.example.com
`), 0o600))
	// It includes itself, ssh gives up on that at some depth.
	require.NoError(t, os.WriteFile(filepath.Join(sshDir, "extra"), []byte(
		"Host \"nas\"\n  ProxyCommand nc 192.0.2.9 22\nInclude extra\n",
	), 0o600))

	st := &state.State{}
	for i, name := range []string{"bastion", "JUMP", "prod-db", "mirror", "nas", "web", "prod-open", "other"} {
		st.Targets = append(st.Targets, state.Target{
			ID: fmt.Sprintf("t-%d", i+1), Name: name, Usernames: []string{"root"},
		})
	}
	// Twice, the second run sees the file the first one wrote.
	writtenConfig(t, st)
	out := writtenConfig(t, st)

	// JUMP differs from the user's jump only by case. ssh's Match does not
	// tell those apart, and neither does a person.
	for _, taken := range []string{"bastion", "JUMP", "prod-db", "mirror", "nas"} {
		assert.NotContains(t, out, "\nHost "+taken+"\n", "%s is the user's own name", taken)
		assert.Contains(t, out, "\nHost nokku/"+taken+"\n", "%s stays reachable under the prefix", taken)
	}
	for name, why := range map[string]string{
		"web":       "a block that sends the name nowhere only adds options",
		"prod-open": "the user's pattern leaves it out",
		"other":     "Host * holds defaults",
	} {
		assert.Contains(t, out, "\nHost "+name+"\n", why)
	}
	assert.Equal(t, map[string]string{
		"t-1": "nokku/bastion", "t-2": "nokku/JUMP", "t-3": "nokku/prod-db", "t-4": "nokku/mirror", "t-5": "nokku/nas",
		"t-6": "web", "t-7": "prod-open", "t-8": "other",
	}, HostAliases(st), "nk ls shows the names ssh knows")
}

// Two servers never share a Host line, and names that differ only by case
// count as one.
func TestHostLinesAreNeverShared(t *testing.T) {
	setupSSHDir(t)
	st := &state.State{
		Targets: []state.Target{
			{ID: "t-1", Name: "db", Usernames: []string{"root"}},
			{ID: "t-2", Name: "DB", Usernames: []string{"root"}},
			{ID: "t-3", Name: "Db", Usernames: []string{"root"}},
			{ID: "t-4", Name: "cache", Usernames: []string{"root"}},
		},
	}
	out := writtenConfig(t, st)

	for _, host := range []string{"nokku/t-1", "nokku/t-2", "nokku/t-3", "cache"} {
		assert.Contains(t, out, "\nHost "+host+"\n")
	}
	seen := map[string]bool{}
	for line := range strings.SplitSeq(out, "\n") {
		host, ok := strings.CutPrefix(line, "Host ")
		if !ok {
			continue
		}
		host = strings.ToLower(host)
		assert.False(t, seen[host], "%s is written twice", host)
		seen[host] = true
	}
	assert.Len(t, seen, 4)
}
