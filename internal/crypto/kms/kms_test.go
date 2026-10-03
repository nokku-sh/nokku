package kms

import (
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/testdb"
)

const (
	secretA = "secret-a-0123456789-0123456789-01"
	secretB = "secret-b-0123456789-0123456789-01"
)

func TestMain(m *testing.M) {
	// A developer's KMS settings must not reach the tests.
	os.Unsetenv("KMS_URI")
	testdb.Setup("kms")
	os.Exit(m.Run())
}

// freshDB returns a connection to a database without a keyset.
func freshDB(t *testing.T) *db.Connection {
	t.Helper()
	conn, err := db.NewConnection(t.Context())
	if err != nil {
		t.Skipf("no test database: %v", err)
	}
	admin, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	defer func() { _ = admin.Close(t.Context()) }()
	_, err = admin.Exec(t.Context(), "DELETE FROM keysets")
	require.NoError(t, err)
	return conn
}

// keyID is the Tink prefix that names the key a ciphertext was made with.
func keyID(ciphertext []byte) string {
	return string(ciphertext[:5])
}

func TestKeysetSurvivesRestart(t *testing.T) {
	conn := freshDB(t)
	first, err := New(t.Context(), conn, secretA)
	require.NoError(t, err)
	ciphertext, err := first.Encrypt([]byte("ca private key"))
	require.NoError(t, err)

	again, err := New(t.Context(), conn, secretA)
	require.NoError(t, err)
	plaintext, err := again.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, "ca private key", string(plaintext))

	_, err = New(t.Context(), conn, secretB)
	assert.Error(t, err, "a wrong NOKKU_SECRET must fail at boot, not run with broken keys")
}

// A new secret takes one row. Everything written before stays readable, and
// nothing written after is in reach of the old secret.
func TestRotateSecret(t *testing.T) {
	conn := freshDB(t)
	enc, err := New(t.Context(), conn, secretA)
	require.NoError(t, err)
	before, err := enc.Encrypt([]byte("recording frame"))
	require.NoError(t, err)

	require.NoError(t, enc.Rotate(t.Context(), "secret:"+secretB))

	_, err = New(t.Context(), conn, secretA)
	require.Error(t, err, "the old secret still opens the keyset")

	rotated, err := New(t.Context(), conn, secretB)
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
	enc, err := New(t.Context(), conn, secretA)
	require.NoError(t, err)

	for _, target := range []string{"secret:short", "secret:", "aws-kms://key", "kms:aws-kms://key", ""} {
		require.Error(t, enc.Rotate(t.Context(), target), "target %q", target)
	}
	_, err = New(t.Context(), conn, secretA)
	assert.NoError(t, err, "a refused rotation changed the keyset")
}

// With a KMS the timer adds a data key once the primary is old enough, and
// rewraps without one before that.
func TestTimedRotation(t *testing.T) {
	conn := freshDB(t)
	enc := &TinkEncryptor{db: conn, kek: fakeKEK{id: 1}, RotateInterval: time.Hour}
	require.NoError(t, enc.load(t.Context()))
	before, err := enc.Encrypt([]byte("sso client secret"))
	require.NoError(t, err)

	require.NoError(t, enc.update(t.Context(), enc.kek, false))
	same, err := enc.Encrypt([]byte("x"))
	require.NoError(t, err)
	assert.Equal(t, keyID(before), keyID(same), "rotated before the interval passed")

	enc.RotateInterval = time.Nanosecond
	require.NoError(t, enc.update(t.Context(), enc.kek, false))
	after, err := enc.Encrypt([]byte("x"))
	require.NoError(t, err)
	assert.NotEqual(t, keyID(before), keyID(after), "no new data key after the interval")

	plaintext, err := enc.Decrypt(before)
	require.NoError(t, err, "data from before the rotation is unreadable")
	assert.Equal(t, "sso client secret", string(plaintext))

	// A restart reads the rotated keyset back.
	restarted := &TinkEncryptor{db: conn, kek: fakeKEK{id: 1}}
	require.NoError(t, restarted.load(t.Context()))
	plaintext, err = restarted.Decrypt(after)
	require.NoError(t, err)
	assert.Equal(t, "x", string(plaintext))
}

func TestValidSecret(t *testing.T) {
	require.NoError(t, ValidSecret(secretA))
	require.Error(t, ValidSecret(""))
	require.Error(t, ValidSecret("too-short"))
	require.Error(t, ValidSecret("CHANGE_ME_generate_with_openssl_rand"))
	assert.Error(t, ValidSecret("0123456789abcdefghijklmnopqrstuv"))
}
