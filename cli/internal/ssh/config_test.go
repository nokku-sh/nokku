package ssh

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/cli/internal/paths"
	"github.com/nokku-sh/nokku/cli/internal/state"
)

func TestRenderSSHHosts(t *testing.T) {
	setupSSHDir(t)
	st := &state.State{
		Targets: []state.Target{
			{ID: "t-1", Name: "web", Usernames: []string{"alice", "bob"}},
			{ID: "t-2", Name: "DB", Usernames: []string{"alice"}},
			{ID: "t-4", Name: "no-users"},
			{ID: "t-5", Name: "prod\n    ProxyCommand curl evil", Usernames: []string{"a"}},
			{ID: "t-6", Name: "ok", Usernames: []string{"a\n    ProxyCommand curl evil"}},
			{ID: "t-7", Name: "a/b", Usernames: []string{"a"}},
			{ID: "t-8", Name: "github.com", Usernames: []string{"git"}},
			{ID: "t-9", Name: "10.0.0.5", Usernames: []string{"root"}},
			{ID: "t-10", Name: "wild", Usernames: []string{"*"}},
		},
	}
	out := string(renderSSHHosts(st, "nk"))

	for _, want := range []string{
		"Host web.nk\nMatch originalhost web.nk exec \"nk prepare t-1\"\n    User alice\n" +
			"    ProxyCommand nk proxy t-1 %p\n    HostKeyAlias t-1\n",
		"    CertificateFile " + configValue(paths.SSHCertificate("t-1")) + "\n",
		"    IdentityAgent " + configValue(paths.AgentSocket()) + "\n",
		// A Host * of the user never forwards to a target.
		"    ForwardAgent no\n    ForwardX11 no\n",
		// One lowercase name a server, whatever its case in the core.
		"Host db.nk\nMatch originalhost db.nk exec \"nk prepare t-2\"\n    User alice\n",
	} {
		assert.Contains(t, out, want)
	}
	// A server names its own targets only. It never claims a real host.
	for _, forbidden := range []string{
		"no-users", "curl evil", "a/b", "github.com", "10.0.0.5", "wild",
	} {
		assert.NotContains(t, out, forbidden)
	}
	assert.Equal(t, "db.nk", Host(st.Targets[1]), "nk ls shows the names ssh knows")
	assert.Empty(t, Host(st.Targets[2]), "a server without an account has no name for ssh")
}

// One block for every name under .nk, and no token in it: a host name never reaches a shell.
func TestRenderSSHConfig(t *testing.T) {
	setupSSHDir(t)
	out := string(renderSSHConfig("/usr/bin/nk"))

	assert.Equal(t, header+
		"Match originalhost *.nk exec \"/usr/bin/nk prepare\"\n"+
		"    "+includeLine(paths.SSHHostsFile())+"\n"+
		"    ProxyCommand /usr/bin/nk proxy\n", out)
	assert.NotContains(t, out, "%", "a token would hand what the user typed to a shell")
}

// The real ssh reads what nk writes: only a name under .nk runs nk prepare, before the hosts file.
func TestSSHReadsTheConfigAsMeant(t *testing.T) {
	sshBin, err := exec.LookPath("ssh")
	if err != nil || runtime.GOOS == "windows" {
		t.Skip("needs an OpenSSH client and a shell")
	}
	setupSSHDir(t)
	dir := t.TempDir()
	calls, synced, fake := filepath.Join(dir, "calls"), filepath.Join(dir, "synced"), filepath.Join(dir, "nk")
	st := &state.State{Targets: []state.Target{{ID: "t-1", Name: "Web", Usernames: []string{"alice"}}}}
	// The stand-in for nk. A prepare without an id puts the hosts file there, like a sync does.
	require.NoError(t, os.WriteFile(synced, renderSSHHosts(st, fake), 0o600))
	require.NoError(t, os.WriteFile(fake, []byte("#!/bin/sh\necho \"$*\" >> "+calls+"\n"+
		"[ \"$*\" = prepare ] && cp "+synced+" "+paths.SSHHostsFile()+"\nexit 0\n"), 0o700))
	require.NoError(t, os.WriteFile(paths.SSHConfigFile(), renderSSHConfig(fake), 0o600))
	resolve := func(host string) string {
		t.Helper()
		out, sshErr := exec.CommandContext(t.Context(), sshBin, "-F", paths.SSHConfigFile(), "-G", host).
			CombinedOutput()
		require.NoError(t, sshErr, string(out))
		return string(out)
	}
	called := func() string {
		data, readErr := os.ReadFile(calls)
		if readErr != nil {
			return ""
		}
		return string(data)
	}

	own := resolve("example.com")
	assert.Empty(t, called(), "a host of the user's own started nk")
	assert.NotContains(t, own, fake)

	// The server is Web in the core, and people type what they read there.
	known := resolve("Web.nk")
	assert.Equal(t, "prepare\nprepare t-1\n", called(), "first the hosts, then the certificate of the one")
	assert.Contains(t, known, "user alice\n")
	assert.Contains(t, known, "hostkeyalias t-1\n")
	assert.Contains(
		t,
		known,
		"proxycommand "+fake+" proxy t-1 %p\n",
		"the hosts file was read after nk prepare wrote it",
	)

	assert.Contains(
		t,
		resolve("typo.nk"),
		"proxycommand "+fake+" proxy\n",
		"an unknown name ends in nk proxy, which says so",
	)
}

// ssh signs through the key itself, the nk agent holds nothing for it.
func TestRenderSSHConfigSecurityKey(t *testing.T) {
	setupSSHDir(t)
	st := &state.State{
		SecurityKey: true,
		Targets:     []state.Target{{ID: "t-1", Name: "web", Usernames: []string{"alice"}}},
	}
	out := string(renderSSHHosts(st, "nk"))

	assert.Contains(t, out, "    IdentityFile "+configValue(paths.SecurityKeyFile())+"\n")
	assert.Contains(t, out, "    IdentityAgent none\n")
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
		CA: &state.CA{UserPublicKey: "ssh-ed25519 AAAAUser1==", HostPublicKey: "ssh-ed25519 AAAACa1== production"},
		Targets: []state.Target{
			{ID: "t-1", DaemonID: "d-1"},
			{ID: "t-3", HostPublicKey: "ssh-ed25519 AAAAhost== host"},
			{ID: "t-4"},
			{ID: "t-5", DaemonID: "d-5", HostPublicKey: "ssh-ed25519 AAAAstray"},
		},
	}
	out := string(renderKnownHosts(st))

	assert.Contains(t, out, "@cert-authority t-1 ssh-ed25519 AAAACa1== production\n")
	assert.Contains(t, out, "@cert-authority t-5 ssh-ed25519 AAAACa1== production\n", "every daemon trusts the one CA")
	assert.Contains(t, out, "t-3 ssh-ed25519 AAAAhost== host\n")
	assert.NotContains(t, out, "@cert-authority t-3", "manual targets are pinned, not CA trusted")
	assert.NotContains(t, out, "t-4", "nothing to pin without a host key")
	assert.NotContains(t, out, "AAAAstray", "daemon targets are never pinned by a raw key")
	assert.NotContains(t, out, "AAAAUser1", "the user CA never vouches for a host")

	st.CA = &state.CA{HostPublicKey: "ssh-ed25519 AAAA==\nHost *\n    ProxyCommand curl evil"}
	assert.NotContains(t, string(renderKnownHosts(st)), "curl evil")

	st.CA = nil
	assert.NotContains(t, string(renderKnownHosts(st)), "@cert-authority", "no CA cached means nothing to trust")
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
	assert.Equal(t, includeLine(paths.SSHConfigFile())+"\n\n"+original, string(data), "include goes on top, once")

	require.NoError(t, RemoveInclude())
	data, err = os.ReadFile(cfg)
	require.NoError(t, err)
	assert.Equal(t, original, string(data))
}

func TestIncludeLineQuotesOnlyWhenNeeded(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows paths have backslashes and stay quoted")
	}
	t.Setenv("HOME", "/home/jane")
	assert.Equal(t, "Include /home/jane/.config/nk/ssh_config", includeLine(paths.SSHConfigFile()),
		"zsh and bash completion read the path as written")
	assert.Equal(t, "Include /home/jane/.config/nk/ssh_hosts", includeLine(paths.SSHHostsFile()),
		"and follow it to the hosts, which is where the names to complete are")

	t.Setenv("HOME", "/Users/Jane Doe")
	assert.Equal(t, `Include "/Users/Jane Doe/.config/nk/ssh_config"`, includeLine(paths.SSHConfigFile()))
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
	self, err := os.Executable()
	require.NoError(t, err)
	assert.Equal(t, self, nkCommand(), "ProxyCommand must name this binary")
}
