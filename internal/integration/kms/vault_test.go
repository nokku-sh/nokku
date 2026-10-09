//go:build integration

package kms_test

import (
	"testing"
	"time"
	"uuid"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/internal/crypto/kms"
	"github.com/nokku-sh/nokku/internal/integration/testenv"
)

// testVaultKey starts a Vault, creates a transit key on it and returns the key's KMS URI.
func testVaultKey(t *testing.T) (*api.Client, string, string) {
	t.Helper()
	addr := testenv.Vault(t)
	// The dev server has a self-signed cert.
	t.Setenv("VAULT_SKIP_VERIFY", "true")
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

// A real Vault transit key: boot, restart, rotation in Vault, timed rotation, and the move to NOKKU_SECRET.
func TestVault(t *testing.T) {
	client, name, uri := testVaultKey(t)
	conn := freshDB(t)
	t.Setenv("KMS_URI", uri)

	enc, err := kms.New(t.Context(), conn, "")
	require.NoError(t, err)
	require.True(t, enc.UsesKMS())
	ciphertext, err := enc.Encrypt([]byte("ca private key"))
	require.NoError(t, err)

	readable := func(step string) {
		t.Helper()
		restarted, err := kms.New(t.Context(), conn, "")
		require.NoError(t, err, "%s: the server does not start", step)
		plaintext, err := restarted.Decrypt(ciphertext)
		require.NoError(t, err, "%s: old data is unreadable", step)
		assert.Equal(t, "ca private key", string(plaintext))
	}
	readable("restart")

	// Vault rotates its key. The timer's rewrap moves the keyset to the new version, so the old one can be retired.
	_, err = client.Logical().WriteWithContext(t.Context(), "transit/keys/"+name+"/rotate", nil)
	require.NoError(t, err)
	require.NoError(t, enc.Refresh(t.Context()))
	_, err = client.Logical().WriteWithContext(t.Context(), "transit/keys/"+name+"/config",
		map[string]any{"min_decryption_version": 2})
	require.NoError(t, err)
	readable("after Vault retired its first key version")

	// The timed data key rotation.
	enc.RotateInterval = time.Nanosecond
	require.NoError(t, enc.Refresh(t.Context()))
	fresh, err := enc.Encrypt([]byte("x"))
	require.NoError(t, err)
	assert.NotEqual(t, keyID(ciphertext), keyID(fresh), "no new data key")
	readable("after the data key rotation")

	// Out of Vault to NOKKU_SECRET, and back.
	require.NoError(t, enc.Rotate(t.Context(), "secret:"+secretA))
	t.Setenv("KMS_URI", "")
	bySecret, err := kms.New(t.Context(), conn, secretA)
	require.NoError(t, err)
	require.False(t, bySecret.UsesKMS())
	require.NoError(t, bySecret.Rotate(t.Context(), "kms:"+uri))
	t.Setenv("KMS_URI", uri)
	_, err = kms.New(t.Context(), conn, "")
	require.NoError(t, err, "the keyset did not move back under Vault")
}
