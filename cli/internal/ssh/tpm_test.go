package ssh

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/internal/tpm"

	"github.com/nokku-sh/nokku/cli/internal/paths"
)

// Manual, against a real TPM.
func TestSetupTPMKey(t *testing.T) {
	if os.Getenv("NK_TPM_E2E") == "" {
		t.Skip("manual test: NK_TPM_E2E=1")
	}
	t.Setenv("HOME", t.TempDir())
	probe := tpm.Available()
	if probe != nil {
		t.Skipf("no TPM available: %v", probe)
	}

	require.NoError(t, os.MkdirAll(paths.SSHCertDir(), 0o700))

	setupKey(t, true)
	assert.Equal(t, tpm.MethodTPM, tpm.IdentityMethod(paths.SSHSignerFile()), "expected a TPM identity")
	pub, err := os.ReadFile(paths.PubKeyFile())
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(pub), "ecdsa-sha2-nistp256 "),
		"unexpected TPM public key format: %q", pub)

	// The key file in the state brings the same key back.
	setupKey(t, true)
	pub2, err := os.ReadFile(paths.PubKeyFile())
	require.NoError(t, err)
	assert.Equal(t, string(pub), string(pub2), "TPM public key changed across runs")
}
