//go:build integration

package kms_test

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// docPolicy is the Vault policy core/SECURITY.md gives, for the KEK named kek.
func docPolicy(t *testing.T, kek string) string {
	t.Helper()
	doc, err := os.ReadFile("../../../SECURITY.md")
	require.NoError(t, err)
	_, rest, ok := strings.Cut(string(doc), "```hcl\n")
	require.True(t, ok, "SECURITY.md has no Vault policy")
	policy, _, ok := strings.Cut(rest, "```")
	require.True(t, ok)
	for _, op := range []string{"encrypt", "decrypt"} {
		require.Contains(t, policy, `"transit/`+op+`/nokku"`)
		policy = strings.ReplaceAll(policy, `"transit/`+op+`/nokku"`, `"transit/`+op+`/`+kek+`"`)
	}
	return policy
}

// The policy in SECURITY.md is all the core needs. It lets the KEK only encrypt and decrypt, so nothing the core does
// can delete it.
func TestVaultPolicyFromTheDocs(t *testing.T) {
	conn := freshDB(t)
	root, kek, kekURI := testVaultKey(t)
	token := docToken(t, root, kek, "")
	core, err := root.Clone()
	require.NoError(t, err)
	core.SetToken(token)

	t.Setenv("VAULT_TOKEN", token)
	t.Setenv("KMS_URI", kekURI)
	_, err = openKeyset(t, conn, "")
	require.NoError(t, err, "the policy does not let the core wrap its keyset")

	_, err = core.Logical().WriteWithContext(t.Context(), "transit/keys/"+kek+"/config",
		map[string]any{"deletion_allowed": true})
	require.Error(t, err, "the policy lets the core allow the KEK's deletion")
	_, err = core.Logical().DeleteWithContext(t.Context(), "transit/keys/"+kek)
	require.Error(t, err, "the policy lets the core delete the KEK")
	key, err := root.Logical().ReadWithContext(t.Context(), "transit/keys/"+kek)
	require.NoError(t, err)
	assert.NotNil(t, key, "the KEK is gone")
}
