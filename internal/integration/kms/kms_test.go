//go:build integration

package kms_test

import (
	"context"
	"os"
	"testing"
	"time"
	"uuid"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/crypto/kms"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/integration/testenv"
)

const (
	secretA = "secret-a-0123456789-0123456789-01"
	secretB = "secret-b-0123456789-0123456789-01"
)

func TestMain(m *testing.M) {
	// A developer's KMS settings must not reach the tests.
	os.Unsetenv("KMS_URI")
	stop := testenv.Postgres()
	code := m.Run()
	stop()
	os.Exit(code)
}

// freshDB returns a connection to a database without a keyset.
func freshDB(t *testing.T) *db.Connection {
	t.Helper()
	conn, err := db.NewConnection(t.Context())
	require.NoError(t, err)
	admin, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	defer func() { _ = admin.Close(t.Context()) }()
	_, err = admin.Exec(t.Context(), "DELETE FROM keysets; DELETE FROM sso_providers")
	require.NoError(t, err)
	return conn
}

// storedConfig returns a provider's config column as it sits in the database.
func storedConfig(t *testing.T, ws string) []byte {
	t.Helper()
	admin, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	defer func() { _ = admin.Close(t.Context()) }()
	var raw []byte
	require.NoError(t, admin.QueryRow(t.Context(),
		"SELECT config FROM sso_providers WHERE workspace_id = $1 AND provider_id = 'p'", ws).Scan(&raw))
	return raw
}

// seedProvider stores one encrypted provider config and returns its workspace.
func seedProvider(t *testing.T, conn *db.Connection, secret string) string {
	t.Helper()
	ws := uuid.NewV7().String()
	require.NoError(t, conn.TenantTx(pinned(t, ws), func(q *db.Queries) error {
		if _, err := q.CreateWorkspace(t.Context(), &db.CreateWorkspaceParams{
			ID: ws, Slug: uuid.NewV7().String(), Name: "kms", Settings: &nokkuv1.WorkspaceSettings{},
		}); err != nil {
			return err
		}
		_, err := q.UpsertSSOProvider(t.Context(), &db.UpsertSSOProviderParams{
			ProviderID: "p", Name: "p", Enabled: true, Config: crypto.EncryptedBytes(secret),
		})
		return err
	}))
	return ws
}

func pinned(t *testing.T, ws string) context.Context {
	t.Helper()
	return actor.WithWorkspace(t.Context(), actor.Workspace{ID: ws})
}

func readConfig(t *testing.T, conn *db.Connection, ws string) string {
	t.Helper()
	var row *db.SsoProvider
	require.NoError(t, conn.TenantTx(pinned(t, ws), func(q *db.Queries) (err error) {
		row, err = q.GetSSOProvider(t.Context(), "p")
		return err
	}))
	return string(row.Config)
}

// keyID is the Tink prefix that names the key a ciphertext was made with.
func keyID(ciphertext []byte) string {
	return string(ciphertext[:5])
}

func TestKeysetSurvivesRestart(t *testing.T) {
	conn := freshDB(t)
	first, err := kms.New(t.Context(), conn, secretA)
	require.NoError(t, err)
	ciphertext, err := first.Encrypt([]byte("ca private key"))
	require.NoError(t, err)

	again, err := kms.New(t.Context(), conn, secretA)
	require.NoError(t, err)
	plaintext, err := again.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, "ca private key", string(plaintext))

	_, err = kms.New(t.Context(), conn, secretB)
	assert.Error(t, err, "a wrong NOKKU_SECRET must fail at boot, not run with broken keys")
}

// A new secret takes one row. Everything written before stays readable, and
// nothing written after is in reach of the old secret.
func TestRotateSecret(t *testing.T) {
	conn := freshDB(t)
	enc, err := kms.New(t.Context(), conn, secretA)
	require.NoError(t, err)
	before, err := enc.Encrypt([]byte("recording frame"))
	require.NoError(t, err)

	require.NoError(t, enc.Rotate(t.Context(), "secret:"+secretB))

	_, err = kms.New(t.Context(), conn, secretA)
	require.Error(t, err, "the old secret still opens the keyset")

	rotated, err := kms.New(t.Context(), conn, secretB)
	require.NoError(t, err)
	plaintext, err := rotated.Decrypt(before)
	require.NoError(t, err, "data from before the rotation is unreadable")
	assert.Equal(t, "recording frame", string(plaintext))

	after, err := rotated.Encrypt([]byte("recording frame"))
	require.NoError(t, err)
	assert.NotEqual(t, keyID(before), keyID(after), "the rotation did not add a new data key")

	// The process that rotated keeps working without a restart.
	plaintext, err = enc.Decrypt(after)
	require.NoError(t, err)
	assert.Equal(t, "recording frame", string(plaintext))
}

func TestRotateRefusesBadTarget(t *testing.T) {
	conn := freshDB(t)
	enc, err := kms.New(t.Context(), conn, secretA)
	require.NoError(t, err)

	for _, target := range []string{"secret:short", "secret:", "aws-kms://key", "kms:aws-kms://key", ""} {
		require.Error(t, enc.Rotate(t.Context(), target), "target %q", target)
	}
	_, err = kms.New(t.Context(), conn, secretA)
	assert.NoError(t, err, "a refused rotation changed the keyset")
}

// A tick of the timer adds a data key once the primary is old enough, and
// only rewraps before that. The timer itself runs with a KMS, see TestVault.
func TestTimedRotation(t *testing.T) {
	conn := freshDB(t)
	enc, err := kms.New(t.Context(), conn, secretA)
	require.NoError(t, err)
	enc.RotateInterval = time.Hour
	before, err := enc.Encrypt([]byte("sso client secret"))
	require.NoError(t, err)

	require.NoError(t, enc.Refresh(t.Context()))
	same, err := enc.Encrypt([]byte("x"))
	require.NoError(t, err)
	assert.Equal(t, keyID(before), keyID(same), "rotated before the interval passed")

	enc.RotateInterval = time.Nanosecond
	require.NoError(t, enc.Refresh(t.Context()))
	after, err := enc.Encrypt([]byte("x"))
	require.NoError(t, err)
	assert.NotEqual(t, keyID(before), keyID(after), "no new data key after the interval")

	plaintext, err := enc.Decrypt(before)
	require.NoError(t, err, "data from before the rotation is unreadable")
	assert.Equal(t, "sso client secret", string(plaintext))

	// A restart reads the rotated keyset back.
	restarted, err := kms.New(t.Context(), conn, secretA)
	require.NoError(t, err)
	plaintext, err = restarted.Decrypt(after)
	require.NoError(t, err)
	assert.Equal(t, "x", string(plaintext))
}

// A rotation moves what the database holds to the new key and then drops the
// older keys, so the keyset never grows past two.
func TestRotationReencryptsAndPrunes(t *testing.T) {
	conn := freshDB(t)
	enc, err := kms.New(t.Context(), conn, secretA)
	require.NoError(t, err)
	require.NoError(t, crypto.SetEncryptor(enc))
	ws := seedProvider(t, conn, "sso client secret")
	// One ciphertext per round, made with the key that round replaces.
	var detached [][]byte

	for round := range 3 {
		made, err := enc.Encrypt([]byte("not in the database"))
		require.NoError(t, err)
		detached = append(detached, made)
		require.NoError(t, enc.Rotate(t.Context(), "secret:"+secretA), "round %d", round)

		assert.Equal(
			t,
			"sso client secret",
			readConfig(t, conn, ws),
			"round %d: the stored secret is unreadable",
			round,
		)

		fresh, err := enc.Encrypt([]byte("x"))
		require.NoError(t, err)
		assert.Equal(t, keyID(fresh), keyID(storedConfig(t, ws)), "round %d: the stored secret kept an old key", round)

		// Two keys stay, the new one and the one it replaced.
		_, err = enc.Decrypt(detached[round])
		require.NoError(t, err, "round %d: the replaced key is gone too early", round)
		for _, older := range detached[:round] {
			_, err := enc.Decrypt(older)
			require.Error(t, err, "round %d: old keys were not dropped", round)
		}
	}

	// A restart sees the same thing.
	restarted, err := kms.New(t.Context(), conn, secretA)
	require.NoError(t, err)
	require.NoError(t, crypto.SetEncryptor(restarted))
	assert.Equal(t, "sso client secret", readConfig(t, conn, ws))
}
