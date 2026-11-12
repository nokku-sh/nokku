package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nokku/cli/internal/paths"
	"github.com/nokku-sh/nokku/cli/internal/ssh"
	"github.com/nokku-sh/nokku/cli/internal/state"
	"github.com/nokku-sh/nokku/internal/nktoken"
)

func setHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	require.NoError(t, paths.EnsureDirs())
}

// runFlags parses args with the real root flags and returns the state.
func runFlags(t *testing.T, args ...string) (*state.State, error) {
	t.Helper()
	// The flags read these, and a developer's shell must not leak in.
	for _, env := range []string{"NK_API_URL", "NK_REQUIRE_TPM", "NK_CA_FILE", "NK_DEBUG"} {
		t.Setenv(env, "")
		require.NoError(t, os.Unsetenv(env))
	}
	var (
		s   *state.State
		err error
	)
	load := func(_ context.Context, cmd *cli.Command) error {
		s, err = loadState(cmd)
		return nil
	}
	root := Root()
	root.Action = load
	for _, sub := range root.Commands {
		sub.Action = load
	}
	require.NoError(t, root.Run(t.Context(), append([]string{"nk"}, args...)))
	return s, err
}

func TestLoadStateKeepsStoredAPI(t *testing.T) {
	setHome(t)
	require.NoError(t, (&state.State{
		APIURL: "https://self.example", SessionToken: "sess",
		Targets: []state.Target{{ID: "t"}},
	}).Save())

	s, err := runFlags(t)
	require.NoError(t, err)
	assert.Equal(t, "https://self.example", s.APIURL, "a run without the flag must keep the stored server")
	assert.Equal(t, "sess", s.SessionToken)
}

// Every workspace has an address of its own, so a fresh nk has none to fall back to.
func TestNoAddressUntilOneIsGiven(t *testing.T) {
	setHome(t)
	s, err := runFlags(t)
	require.NoError(t, err)
	require.Empty(t, s.APIURL)
	_, err = newClient(s)
	assert.ErrorContains(t, err, "--api")
}

func TestLoadStateNewAPIDropsSession(t *testing.T) {
	setHome(t)
	require.NoError(t, (&state.State{
		APIURL: "https://a.example", SessionToken: "sess", SecurityKey: true,
		Targets: []state.Target{{ID: "t"}},
	}).Save())

	s, err := runFlags(t, "--api", "https://b.example")
	require.NoError(t, err)
	assert.Equal(t, "https://b.example", s.APIURL)
	assert.Empty(t, s.SessionToken, "a session never goes to another server")
	assert.Empty(t, s.Targets)
	assert.True(t, s.SecurityKey, "another server must not quietly drop the security key")
}

// ssh runs nk proxy without flags, so a TPM asked for once must stay asked for.
func TestLoadStateKeepsRequireTPM(t *testing.T) {
	setHome(t)
	s, err := runFlags(t, "--api", "https://a.example", "--require-tpm")
	require.NoError(t, err)
	require.True(t, s.RequireTPM)
	require.NoError(t, s.Save())

	s, err = runFlags(t)
	require.NoError(t, err)
	assert.True(t, s.RequireTPM, "a run without the flag dropped it")

	s, err = runFlags(t, "--api", "https://b.example")
	require.NoError(t, err)
	assert.True(t, s.RequireTPM, "another server must not quietly drop it")
}

// Plain http would carry the session or a service account token in the clear.
func TestLoadStateRefusesPlainHTTP(t *testing.T) {
	setHome(t)
	_, err := runFlags(t, "--api", "http://nokku.corp")
	require.ErrorContains(t, err, "not encrypted")

	for _, args := range [][]string{
		{"--api", "http://localhost:8080"},
		{"--api", "http://127.0.0.1:8080"},
		{"--api", "http://[::1]:8080"},
	} {
		_, err = runFlags(t, args...)
		require.NoError(t, err, "%v", args)
	}

	require.NoError(t, (&state.State{APIURL: "http://nokku.corp", SessionToken: "sess"}).Save())
	_, err = runFlags(t)
	require.ErrorContains(t, err, "not encrypted", "a stored server is held to the same rule")
}

func TestLoadStateCAFile(t *testing.T) {
	setHome(t)
	path := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(path, []byte("not a certificate"), 0o600))
	_, err := runFlags(t, "--api", "https://nokku.corp", "--ca-file", path)
	require.ErrorContains(t, err, "no certificate")

	_, err = runFlags(t, "--api", "https://nokku.corp", "--ca-file", filepath.Join(t.TempDir(), "missing.pem"))
	require.ErrorContains(t, err, "CA file")
}

// The CA of one server never vouches for another.
func TestLoadStateDropsCAOnServerChange(t *testing.T) {
	setHome(t)
	require.NoError(t, (&state.State{APIURL: "https://a.example", APICA: "pem"}).Save())

	s, err := runFlags(t)
	require.NoError(t, err)
	assert.Equal(t, "pem", s.APICA)

	s, err = runFlags(t, "--api", "https://b.example")
	require.NoError(t, err)
	assert.Empty(t, s.APICA)
}

func TestLoadStateRejectsNonServiceToken(t *testing.T) {
	setHome(t)
	for _, token := range []string{
		"nk_sess_" + strings.Repeat("a", 34),
		"nk_sa_" + strings.Repeat("a", 38), // the old format
		"nk_sa_abc",
		"nk_sa_" + strings.Repeat("a", 34), // a whole key with a wrong checksum
	} {
		t.Setenv("NK_TOKEN", token)
		_, err := runFlags(t)
		require.ErrorContains(t, err, "nk_sa_", "%q", token)
	}

	t.Setenv("NK_TOKEN", nktoken.New("sa"))
	s, err := runFlags(t)
	require.NoError(t, err)
	assert.True(t, s.IsServiceAccount())
	assert.True(t, s.SessionValid())
}

func TestDropSecurityKey(t *testing.T) {
	setHome(t)
	handle := paths.SecurityKeyFile()
	require.NoError(t, os.WriteFile(handle, []byte("handle"), 0o600))
	require.NoError(t, os.WriteFile(handle+".pub", []byte("sk-ssh-ed25519@openssh.com AAAA x@nokku\n"), 0o600))
	s := &state.State{
		SecurityKey: true,
		Targets:     []state.Target{{ID: "t-1", Name: "web", Usernames: []string{"root"}}},
	}
	require.NoError(t, s.Save())
	require.NoError(t, ssh.WriteConfigs(s))

	require.NoError(t, dropSecurityKey(s))
	assert.False(t, state.Load().SecurityKey, "kept for later runs")
	assert.NoFileExists(t, handle, "a later --security-key makes a new key")
	assert.NoFileExists(t, handle+".pub")
	config, err := os.ReadFile(paths.SSHConfigFile())
	require.NoError(t, err)
	assert.NotContains(t, string(config), "security-key")
	assert.NotContains(t, string(config), "IdentityAgent none", "ssh signs through the nk agent again")
}

// Any local user can read a command line, so a secret comes from the environment or a prompt.
func TestNoFlagTakesASecret(t *testing.T) {
	var walk func(c *cli.Command)
	walk = func(c *cli.Command) {
		for _, f := range c.Flags {
			for _, name := range f.Names() {
				for _, word := range []string{"token", "secret", "password"} {
					assert.NotContains(t, name, word, "%s --%s", c.Name, name)
				}
				assert.NotEqual(t, "key", name, "%s --%s", c.Name, name)
			}
		}
		for _, sub := range c.Commands {
			walk(sub)
		}
	}
	root := Root()
	require.NotEmpty(t, root.Commands)
	walk(root)
}

// An older nk would misread a newer config and then save over it.
func TestLoadStateRefusesANewerConfig(t *testing.T) {
	setHome(t)
	require.NoError(t, (&state.State{APIURL: "https://a.example"}).Save())
	raw, err := os.ReadFile(paths.ConfigFile())
	require.NoError(t, err)
	require.Contains(t, string(raw), `"version": 1`)

	newer := strings.Replace(string(raw), `"version": 1`, `"version": 2`, 1)
	require.NoError(t, os.WriteFile(paths.ConfigFile(), []byte(newer), 0o600))
	_, err = runFlags(t)
	require.ErrorContains(t, err, "newer nk")
}
