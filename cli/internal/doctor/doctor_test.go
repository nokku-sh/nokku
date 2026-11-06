package doctor

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/cli/internal/paths"
	"github.com/nokku-sh/nokku/cli/internal/state"
)

func TestExitCode(t *testing.T) {
	t.Parallel()
	for want, checks := range [][]Check{
		{{Status: statusOK}, {Status: statusInfo}},
		{{Status: statusOK}, {Status: statusWarn}},
		{{Status: statusWarn}, {Status: statusFail}},
	} {
		r := Report{Checks: checks}
		assert.Equal(t, want, r.ExitCode())
	}
}

func TestCheckSecurityKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	require.NoError(t, paths.EnsureDirs())
	identity := func() Check {
		var r Report
		checkSecurityKey(&r)
		require.NotEmpty(t, r.Checks)
		return r.Checks[0]
	}

	assert.Equal(t, statusFail, identity().Status, "no handle file")

	require.NoError(t, os.WriteFile(paths.SecurityKeyFile(), []byte("handle"), 0o600))
	require.NoError(t, os.WriteFile(paths.SecurityKeyFile()+".pub", []byte("sk-ssh-ed25519@openssh.com "+
		"AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIFnqlkEEgnnAYIr5pXed65L5FfJ5iwFb/dx4g0LI+YJeAAAACXNzaDpub2trdQ== x\n"),
		0o600))
	got := identity()
	assert.Equal(t, statusOK, got.Status, got.Detail)
	assert.Contains(t, got.Detail, "sk-ssh-ed25519@openssh.com")
}

// A missing cache leaves no CA, which must not make every certificate stale.
func TestRepairKeepsCertsWithoutCache(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	require.NoError(t, paths.EnsureDirs())
	cert := paths.SSHCertificate("0199a0a0-0000-7000-8000-000000000002")
	require.NoError(t, os.WriteFile(cert, []byte("cert"), 0o600))

	fixed := repair(&state.State{})
	assert.FileExists(t, cert, "a certificate must survive a repair with no cached state")
	assert.Contains(t, fixed, "added the Nokku include to ~/.ssh/config")

	fixed = repair(&state.State{
		User:    &state.User{ID: "u"},
		Targets: []state.Target{{ID: "t", Name: "prod"}},
	})
	assert.NoFileExists(t, cert)
	assert.Contains(t, fixed, "removed 1 stale certificates")
	assert.NotContains(t, fixed, "added the Nokku include to ~/.ssh/config", "only real changes are reported")
}
