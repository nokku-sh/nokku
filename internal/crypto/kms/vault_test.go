package kms

import (
	"os"
	"testing"
	"time"
	"uuid"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testVaultKey creates a transit key on the Vault from compose.test.yml and
// returns its KMS URI. The test skips without that Vault.
func testVaultKey(t *testing.T) (*api.Client, string, string) {
	t.Helper()
	// The dev server has a self-signed cert and the root token "root".
	t.Setenv("VAULT_SKIP_VERIFY", "true")
	t.Setenv("VAULT_TOKEN", "root")
	cfg := api.DefaultConfig()
	cfg.Address = "https://localhost:8200"
	cfg.Timeout = 2 * time.Second
	cfg.MaxRetries = 0
	client, err := api.NewClient(cfg)
	require.NoError(t, err)
	if _, err := client.Sys().HealthWithContext(t.Context()); err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("no test Vault in CI: %v", err)
		}
		t.Skipf("no test Vault: %v", err)
	}

	mounts, err := client.Sys().ListMountsWithContext(t.Context())
	require.NoError(t, err)
	if _, ok := mounts["transit/"]; !ok {
		require.NoError(t, client.Sys().MountWithContext(t.Context(), "transit", &api.MountInput{Type: "transit"}))
	}
	name := "nokku-test-" + uuid.New().String()
	_, err = client.Logical().WriteWithContext(t.Context(), "transit/keys/"+name, nil)
	require.NoError(t, err)
	return client, name, "hcvault://localhost:8200/transit/keys/" + name
}

// The keyset wrapped by a real Vault transit key: boot, restart, a key
// rotation inside Vault, the timed data key rotation, and the move between
// Vault and NOKKU_SECRET.
func TestVault(t *testing.T) {
	client, name, uri := testVaultKey(t)
	conn := freshDB(t)
	t.Setenv("KMS_URI", uri)

	enc, err := New(t.Context(), conn, "")
	require.NoError(t, err)
	require.True(t, enc.UsesKMS())
	ciphertext, err := enc.Encrypt([]byte("ca private key"))
	require.NoError(t, err)

	readable := func(step string) {
		t.Helper()
		restarted, err := New(t.Context(), conn, "")
		require.NoError(t, err, "%s: the server does not start", step)
		plaintext, err := restarted.Decrypt(ciphertext)
		require.NoError(t, err, "%s: old data is unreadable", step)
		assert.Equal(t, "ca private key", string(plaintext))
	}
	readable("restart")

	// Vault rotates its key. The timer's rewrap moves the keyset to the new
	// version, so the old one can be retired in Vault.
	_, err = client.Logical().WriteWithContext(t.Context(), "transit/keys/"+name+"/rotate", nil)
	require.NoError(t, err)
	require.NoError(t, enc.update(t.Context(), enc.currentKEK(), false))
	_, err = client.Logical().WriteWithContext(t.Context(), "transit/keys/"+name+"/config",
		map[string]any{"min_decryption_version": 2})
	require.NoError(t, err)
	readable("after Vault retired its first key version")

	// The timed data key rotation.
	enc.RotateInterval = time.Nanosecond
	require.NoError(t, enc.update(t.Context(), enc.currentKEK(), false))
	fresh, err := enc.Encrypt([]byte("x"))
	require.NoError(t, err)
	assert.NotEqual(t, keyID(ciphertext), keyID(fresh), "no new data key")
	readable("after the data key rotation")

	// Out of Vault to NOKKU_SECRET, and back.
	require.NoError(t, enc.Rotate(t.Context(), "secret:"+secretA))
	t.Setenv("KMS_URI", "")
	bySecret, err := New(t.Context(), conn, secretA)
	require.NoError(t, err)
	require.False(t, bySecret.UsesKMS())
	require.NoError(t, bySecret.Rotate(t.Context(), "kms:"+uri))
	t.Setenv("KMS_URI", uri)
	_, err = New(t.Context(), conn, "")
	require.NoError(t, err, "the keyset did not move back under Vault")
}
