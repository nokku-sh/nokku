package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nokku/cli/internal/paths"
	"github.com/nokku-sh/nokku/cli/internal/state"
)

func setHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	require.NoError(t, paths.EnsureDirs())
}

// runFlags parses args with the real root flags and returns the resulting state.
func runFlags(t *testing.T, args ...string) (*state.State, error) {
	t.Helper()
	// The flags read these, and a developer's shell must not leak in.
	for _, env := range []string{"NK_API_URL", "NK_TTL", "NK_REQUIRE_TPM", "NK_API_PIN", "NK_CA_FILE", "NK_DEBUG"} {
		t.Setenv(env, "")
		require.NoError(t, os.Unsetenv(env))
	}
	var (
		s   *state.State
		err error
	)
	root := Root()
	root.Action = func(_ context.Context, cmd *cli.Command) error {
		s, err = loadState(cmd)
		return nil
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
	assert.Equal(t, "https://self.example", s.APIURL, "the default must not override a stored server")
	assert.Equal(t, "sess", s.SessionToken)
}

func TestLoadStateNewAPIDropsSession(t *testing.T) {
	setHome(t)
	require.NoError(t, (&state.State{
		APIURL: "https://a.example", SessionToken: "sess",
		Targets: []state.Target{{ID: "t"}},
	}).Save())

	s, err := runFlags(t, "--api", "https://b.example")
	require.NoError(t, err)
	assert.Equal(t, "https://b.example", s.APIURL)
	assert.Empty(t, s.SessionToken, "a session never goes to another server")
	assert.Empty(t, s.Targets)
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
	t.Setenv("NK_TOKEN", "sess-abc")
	_, err := runFlags(t)
	require.ErrorContains(t, err, "nk_sa_")

	t.Setenv("NK_TOKEN", "nk_sa_abc")
	s, err := runFlags(t)
	require.NoError(t, err)
	assert.True(t, s.IsServiceAccount())
	assert.True(t, s.SessionValid())
}
