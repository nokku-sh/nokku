//go:build integration

package ssh_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/crypto"
	"github.com/nokku-sh/nokku/core/internal/crypto/kms"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/integration/testenv"
	"github.com/nokku-sh/nokku/core/internal/ssh"
)

func TestMain(m *testing.M) {
	stop := testenv.Postgres()
	code := m.Run()
	stop()
	os.Exit(code)
}

func rotationConn(t *testing.T) (*db.Connection, *kms.Keyset) {
	t.Helper()
	conn, err := db.NewConnection(t.Context())
	require.NoError(t, err)
	t.Setenv("NOKKU_SECRET", "test-secret-0123456789-0123456789")
	keys, err := kms.New(t.Context(), conn, false)
	require.NoError(t, err)
	return conn, keys
}

func seedCA(t *testing.T, conn *db.Connection, keys *kms.Keyset, workspaceID string) *db.SSHCA {
	t.Helper()
	var ca *db.SSHCA
	require.NoError(t, conn.TenantTx(testenv.Pinned(t, workspaceID), func(q *db.Queries) (err error) {
		ca, err = ssh.CreateCA(t.Context(), q, keys, ssh.NewCA())
		return err
	}))
	return ca
}

func seedWorkspace(t *testing.T, conn *db.Connection) string {
	t.Helper()
	workspaceID := uuid.NewV7().String()
	require.NoError(t, conn.TenantTx(testenv.Pinned(t, workspaceID), func(q *db.Queries) error {
		_, err := q.CreateWorkspace(t.Context(), &db.CreateWorkspaceParams{
			ID: workspaceID, Slug: uuid.NewV7().String(), Name: "rotate",
			Settings: &nokkuv1.WorkspaceSettings{},
		})
		return err
	}))
	return workspaceID
}

func signer(t *testing.T, conn *db.Connection, keys *kms.Keyset, ca *db.SSHCA, certType uint32) (gossh.Signer, error) {
	t.Helper()
	var s gossh.Signer
	err := conn.TenantTx(testenv.Pinned(t, ca.WorkspaceID), func(q *db.Queries) (err error) {
		s, err = ssh.CASigner(t.Context(), q, keys, ca.ID, certType)
		return err
	})
	return s, err
}

func newPublicKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := ssh.MarshalPubKey(pub)
	require.NoError(t, err)
	return key
}

func TestRolloverReplacesBothKeys(t *testing.T) {
	conn, keys := rotationConn(t)
	ca := seedCA(t, conn, keys, seedWorkspace(t, conn))
	require.Nil(t, ca.RotatedAt, "a new CA has never been rotated")

	var next *db.SSHCA
	require.NoError(t, conn.TenantTx(testenv.Pinned(t, ca.WorkspaceID), func(q *db.Queries) (err error) {
		current, err := q.GetWorkspaceCAForUpdate(t.Context())
		if err != nil {
			return err
		}
		next, err = ssh.Rollover(t.Context(), q, keys, current)
		return err
	}))
	assert.NotEqual(t, ca.PublicKey, next.PublicKey)
	assert.NotEqual(t, ca.HostPublicKey, next.HostPublicKey, "a rollover replaces both keys")
	require.NotNil(t, next.RotatedAt, "a rollover sets the rotation time")
	assert.WithinDuration(t, time.Now(), *next.RotatedAt, time.Minute)

	// The key rows follow, the CA signs with the new keys only.
	for certType, want := range map[uint32]string{gossh.UserCert: next.PublicKey, gossh.HostCert: next.HostPublicKey} {
		s, err := signer(t, conn, keys, next, certType)
		require.NoError(t, err, "the CA does not sign after the rollover")
		assert.Equal(t, want, ssh.MarshalKey(s.PublicKey()), "the rollover did not replace the key row")
	}
}

// The user key signs logins, the host key servers. ssh-keygen reads what they
// sign as OpenSSH would.
func TestCASignerSignsWithTheKeyOfItsKind(t *testing.T) {
	conn, keys := rotationConn(t)
	ca := seedCA(t, conn, keys, seedWorkspace(t, conn))

	for _, c := range []struct {
		certType           uint32
		authority, other   string
		principal, keygenL string
	}{
		{gossh.UserCert, ca.PublicKey, ca.HostPublicKey, "deploy", "user certificate"},
		{gossh.HostCert, ca.HostPublicKey, ca.PublicKey, "web-1.example.com", "host certificate"},
	} {
		s, err := signer(t, conn, keys, ca, c.certType)
		require.NoError(t, err)
		cert, err := ssh.SignCertificate(
			ca, s, newPublicKey(t), []string{c.principal}, "test", time.Hour, c.certType, ssh.Limits{},
		)
		require.NoError(t, err)
		signedBy := ssh.MarshalKey(cert.SignatureKey)
		assert.Equal(t, c.authority, signedBy, "a %s comes from the wrong key", c.keygenL)
		assert.NotEqual(t, c.other, signedBy)

		path := filepath.Join(t.TempDir(), "id-cert.pub")
		require.NoError(t, os.WriteFile(path, []byte(ssh.MarshalKey(cert)+"\n"), 0o600))
		out, err := exec.CommandContext(t.Context(), "ssh-keygen", "-L", "-f", path).CombinedOutput()
		require.NoError(t, err, "ssh-keygen -L: %s", out)
		authority, _, _, _, err := gossh.ParseAuthorizedKey([]byte(c.authority))
		require.NoError(t, err)
		assert.Contains(t, string(out), c.keygenL)
		assert.Contains(t, string(out), "Signing CA: ED25519 "+gossh.FingerprintSHA256(authority))
		assert.Contains(t, string(out), c.principal)
	}
}

// A key row that is not its CA's signs nothing, swapped in or replaced.
func TestCASignerRefusesAKeyThatIsNotTheCAs(t *testing.T) {
	conn, keys := rotationConn(t)
	ca := seedCA(t, conn, keys, seedWorkspace(t, conn))
	put := func(kind string, sealed []byte) {
		t.Helper()
		require.NoError(t, conn.TenantTx(testenv.Pinned(t, ca.WorkspaceID), func(q *db.Queries) error {
			return q.PutCAKey(t.Context(), &db.PutCAKeyParams{CaID: ca.ID, Kind: kind, PrivateKey: sealed})
		}))
	}

	var host *db.GetCASigningKeyRow
	require.NoError(t, conn.TenantTx(testenv.Pinned(t, ca.WorkspaceID), func(q *db.Queries) (err error) {
		host, err = q.GetCASigningKey(t.Context(), &db.GetCASigningKeyParams{CaID: ca.ID, Kind: "host"})
		return err
	}))
	put("user", host.PrivateKey)
	_, err := signer(t, conn, keys, ca, gossh.UserCert)
	require.Error(t, err, "the host key, moved to the user row, opened")

	// Sealed for the right row, but not the key the CA publishes.
	_, other, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(other)
	require.NoError(t, err)
	aad := crypto.AAD{Table: "ssh_ca_keys", Column: "private_key", Workspace: ca.WorkspaceID, Row: ca.ID + "/user"}
	sealed, err := keys.Seal(aad, der)
	require.NoError(t, err)
	put("user", sealed)
	_, err = signer(t, conn, keys, ca, gossh.UserCert)
	require.ErrorContains(t, err, "does not match", "a key the CA does not publish signs")

	_, err = signer(t, conn, keys, ca, gossh.HostCert)
	assert.NoError(t, err, "the host key is still the CA's")
}
