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
		{{Status: StatusOK}, {Status: StatusInfo}},
		{{Status: StatusOK}, {Status: StatusWarn}},
		{{Status: StatusWarn}, {Status: StatusFail}},
	} {
		r := Report{Checks: checks}
		assert.Equal(t, want, r.ExitCode())
	}
}

// TestRepairKeepsCertsWithoutCache covers the destructive case: a missing
// cache leaves no CAs, which must not read as "every certificate is stale".
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
		Targets: []state.Target{{ID: "t", Name: "prod", CAID: "other"}},
	})
	assert.NoFileExists(t, cert)
	assert.Contains(t, fixed, "removed 1 stale certificates")
	assert.NotContains(t, fixed, "added the Nokku include to ~/.ssh/config", "only real changes are reported")
}
