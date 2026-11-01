//go:build integration

package kms_test

import (
	"testing"
	"uuid"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/integration/testenv"
)

// testVaultKey starts a Vault with a transit key and returns the key's KMS URI.
func testVaultKey(t *testing.T) (*api.Client, string, string) {
	t.Helper()
	addr, caFile := testenv.Vault(t)
	// Verified like a real install. A dev shell's Vault settings stay out.
	for _, name := range []string{
		"VAULT_SKIP_VERIFY", "VAULT_CAPATH", "VAULT_CLIENT_CERT", "VAULT_CLIENT_KEY",
		"VAULT_TLS_SERVER_NAME", "VAULT_NAMESPACE",
	} {
		t.Setenv(name, "")
	}
	t.Setenv("VAULT_CACERT", caFile)
	t.Setenv("VAULT_TOKEN", testenv.VaultToken)
	cfg := api.DefaultConfig()
	cfg.Address = "https://" + addr
	client, err := api.NewClient(cfg)
	require.NoError(t, err)

	require.NoError(t, client.Sys().MountWithContext(t.Context(), "transit", &api.MountInput{Type: "transit"}))
	name := "nokku-test-" + uuid.New().String()
	_, err = client.Logical().WriteWithContext(t.Context(), "transit/keys/"+name, nil)
	require.NoError(t, err)
	return client, name, "hcvault://" + addr + "/transit/keys/" + name
}

// A real Vault transit key: boot, restart, rotation, to NOKKU_SECRET and back.
func TestVault(t *testing.T) {
	client, name, uri := testVaultKey(t)
	conn := freshDB(t)
	t.Setenv("KMS_URI", uri)

	enc, err := openKeyset(t, conn, "")
	require.NoError(t, err)
	require.Equal(t, uri, enc.KMSURI)
	ciphertext, err := enc.Seal(detached, []byte("ca private key"))
	require.NoError(t, err)

	readable := func(step string) {
		t.Helper()
		restarted, err := openKeyset(t, conn, "")
		require.NoError(t, err, "%s: the server does not start", step)
		plaintext, err := restarted.Open(detached, ciphertext)
		require.NoError(t, err, "%s: old data is unreadable", step)
		assert.Equal(t, "ca private key", string(plaintext))
	}
	readable("restart")

	// Vault rotates its key. A rotation to the same URI moves the keyset to the
	// new version, so the old one can go.
	_, err = client.Logical().WriteWithContext(t.Context(), "transit/keys/"+name+"/rotate", nil)
	require.NoError(t, err)
	require.NoError(t, enc.Rotate(t.Context(), "kms:"+uri))
	fresh, err := enc.Seal(detached, []byte("x"))
	require.NoError(t, err)
	assert.NotEqual(t, keyID(ciphertext), keyID(fresh), "no new data key")
	_, err = client.Logical().WriteWithContext(t.Context(), "transit/keys/"+name+"/config",
		map[string]any{"min_decryption_version": 2})
	require.NoError(t, err)
	readable("after Vault retired its first key version")

	// Out of Vault to NOKKU_SECRET, and back.
	require.NoError(t, enc.Rotate(t.Context(), "secret:"+secretA))
	t.Setenv("KMS_URI", "")
	bySecret, err := openKeyset(t, conn, secretA)
	require.NoError(t, err)
	require.Empty(t, bySecret.KMSURI)
	require.NoError(t, bySecret.Rotate(t.Context(), "kms:"+uri))
	t.Setenv("KMS_URI", uri)
	_, err = openKeyset(t, conn, "")
	require.NoError(t, err, "the keyset did not move back under Vault")
}

// With a KMS the whole core starts without NOKKU_SECRET.
func TestCoreStartsWithAKMSAndNoSecret(t *testing.T) {
	freshDB(t)
	_, _, kekURI := testVaultKey(t)
	t.Setenv("KMS_URI", kekURI)
	t.Setenv("NOKKU_SECRET", "")
	t.Setenv("NOKKU_STORAGE_URL", "file://"+t.TempDir())
	t.Setenv("NOKKU_LICENSE_OFFLINE", "true")

	cfg, err := config.New(t.Context(), nil)
	require.NoError(t, err)
	assert.NotEmpty(t, cfg.IAM.DPoP.CurrentNonce())
}
