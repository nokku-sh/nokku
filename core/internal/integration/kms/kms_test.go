//go:build integration

package kms_test

import (
	"context"
	"os"
	"testing"
	"time"
	"uuid"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/crypto"
	"github.com/nokku-sh/nokku/core/internal/crypto/kms"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/iam"
	"github.com/nokku-sh/nokku/core/internal/integration/testenv"
)

const (
	secretA = "secret-a-0123456789-0123456789-01"
	secretB = "secret-b-0123456789-0123456789-01"
)

// detached is the row of a ciphertext in no table, so no rotation converts it.
var detached = crypto.AAD{Table: "nowhere", Column: "secret", Workspace: "none", Row: "1"}

func TestMain(m *testing.M) {
	stop := testenv.Postgres()
	code := m.Run()
	stop()
	os.Exit(code)
}

// openKeyset is a start of the core with NOKKU_SECRET set to secret.
func openKeyset(t *testing.T, conn *db.Connection, secret string) (*kms.Keyset, error) {
	t.Helper()
	t.Setenv("NOKKU_SECRET", secret)
	return kms.New(t.Context(), conn, false)
}

// freshDB returns a connection to a database without a keyset or its secrets.
func freshDB(t *testing.T) *db.Connection {
	t.Helper()
	conn, err := db.NewConnection(t.Context())
	require.NoError(t, err)
	admin, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	defer func() { _ = admin.Close(t.Context()) }()
	_, err = admin.Exec(t.Context(), "DELETE FROM keysets; DELETE FROM sso_providers; DELETE FROM ssh_ca_keys")
	require.NoError(t, err)
	return conn
}

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

func seedProvider(t *testing.T, conn *db.Connection, keys *kms.Keyset, secret string) string {
	t.Helper()
	ws := uuid.NewV7().String()
	sealed, err := keys.Seal(iam.SSOConfigAAD(ws, "p"), []byte(secret))
	require.NoError(t, err)
	require.NoError(t, conn.TenantTx(testenv.Pinned(t, ws), func(q *db.Queries) error {
		if _, err := q.CreateWorkspace(t.Context(), &db.CreateWorkspaceParams{
			ID: ws, Slug: uuid.NewV7().String(), Name: "kms", Settings: &nokkuv1.WorkspaceSettings{},
		}); err != nil {
			return err
		}
		_, err := q.UpsertSSOProvider(t.Context(), &db.UpsertSSOProviderParams{
			ProviderID: "p", Name: "p", Enabled: true, Config: sealed,
		})
		return err
	}))
	return ws
}

func readConfig(t *testing.T, conn *db.Connection, keys *kms.Keyset, ws string) string {
	t.Helper()
	var row *db.SsoProvider
	require.NoError(t, conn.TenantTx(testenv.Pinned(t, ws), func(q *db.Queries) (err error) {
		row, err = q.GetSSOProvider(t.Context(), "p")
		return err
	}))
	config, err := keys.Open(iam.SSOConfigAAD(ws, "p"), row.Config)
	require.NoError(t, err)
	return string(config)
}

// keyID is the Tink prefix that names the key a ciphertext was made with.
func keyID(ciphertext []byte) string {
	return string(ciphertext[:5])
}

func TestKeysetSurvivesRestart(t *testing.T) {
	conn := freshDB(t)
	first, err := openKeyset(t, conn, secretA)
	require.NoError(t, err)
	ciphertext, err := first.Seal(detached, []byte("ca private key"))
	require.NoError(t, err)

	again, err := openKeyset(t, conn, secretA)
	require.NoError(t, err)
	plaintext, err := again.Open(detached, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, "ca private key", string(plaintext))

	_, err = openKeyset(t, conn, secretB)
	assert.Error(t, err, "a wrong NOKKU_SECRET must fail at boot, not run with broken keys")
}

// What was written stays readable, what comes after is out of the old secret's
// reach.
func TestRotateSecret(t *testing.T) {
	conn := freshDB(t)
	enc, err := openKeyset(t, conn, secretA)
	require.NoError(t, err)
	before, err := enc.Seal(detached, []byte("recording frame"))
	require.NoError(t, err)

	require.NoError(t, enc.Rotate(t.Context(), "secret:"+secretB))

	_, err = openKeyset(t, conn, secretA)
	require.Error(t, err, "the old secret still opens the keyset")

	rotated, err := openKeyset(t, conn, secretB)
	require.NoError(t, err)
	plaintext, err := rotated.Open(detached, before)
	require.NoError(t, err, "data from before the rotation is unreadable")
	assert.Equal(t, "recording frame", string(plaintext))

	after, err := rotated.Seal(detached, []byte("recording frame"))
	require.NoError(t, err)
	assert.NotEqual(t, keyID(before), keyID(after), "the rotation did not add a new data key")

	// The process that rotated keeps working without a restart.
	plaintext, err = enc.Open(detached, after)
	require.NoError(t, err)
	assert.Equal(t, "recording frame", string(plaintext))
}

// A running core can't read what a rotation moves, so one blocks the rotation.
func TestRotateRefusesARunningServer(t *testing.T) {
	conn := freshDB(t)
	enc, err := openKeyset(t, conn, secretA)
	require.NoError(t, err)

	ctx, stop := context.WithCancel(t.Context())
	defer stop()
	require.NoError(t, conn.HoldServerLock(ctx))
	require.ErrorIs(t, enc.Rotate(t.Context(), "secret:"+secretB), kms.ErrServerRunning)
	_, err = openKeyset(t, conn, secretA)
	require.NoError(t, err, "a refused rotation changed the keyset")

	stop()
	require.Eventually(t, func() bool {
		return enc.Rotate(t.Context(), "secret:"+secretB) == nil
	}, 5*time.Second, 20*time.Millisecond, "the rotation stayed blocked after the server stopped")
}

func TestRotateRefusesBadTarget(t *testing.T) {
	conn := freshDB(t)
	enc, err := openKeyset(t, conn, secretA)
	require.NoError(t, err)

	for _, target := range []string{"secret:short", "secret:", "aws-kms://key", "kms:aws-kms://key", ""} {
		require.Error(t, enc.Rotate(t.Context(), target), "target %q", target)
	}
	_, err = openKeyset(t, conn, secretA)
	assert.NoError(t, err, "a refused rotation changed the keyset")
}

// A rotation moves the database to the new key and drops older ones, so the
// keyset never grows past two.
func TestRotationReencryptsAndPrunes(t *testing.T) {
	conn := freshDB(t)
	enc, err := openKeyset(t, conn, secretA)
	require.NoError(t, err)
	ws := seedProvider(t, conn, enc, "sso client secret")
	// One ciphertext per round, made with the key that round replaces.
	var replaced [][]byte

	for round := range 3 {
		made, err := enc.Seal(detached, []byte("not in the database"))
		require.NoError(t, err)
		replaced = append(replaced, made)
		require.NoError(t, enc.Rotate(t.Context(), "secret:"+secretA), "round %d", round)

		assert.Equal(
			t,
			"sso client secret",
			readConfig(t, conn, enc, ws),
			"round %d: the stored secret is unreadable",
			round,
		)

		fresh, err := enc.Seal(detached, []byte("x"))
		require.NoError(t, err)
		assert.Equal(t, keyID(fresh), keyID(storedConfig(t, ws)), "round %d: the stored secret kept an old key", round)

		// Two keys stay, the new one and the one it replaced.
		_, err = enc.Open(detached, replaced[round])
		require.NoError(t, err, "round %d: the replaced key is gone too early", round)
		for _, older := range replaced[:round] {
			_, err := enc.Open(detached, older)
			require.Error(t, err, "round %d: old keys were not dropped", round)
		}
	}

	// A restart sees the same thing.
	restarted, err := openKeyset(t, conn, secretA)
	require.NoError(t, err)
	assert.Equal(t, "sso client secret", readConfig(t, conn, restarted, ws))
}
