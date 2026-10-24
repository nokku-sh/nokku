//go:build integration

package ssh_test

import (
	"context"
	"os"
	"testing"
	"time"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/actor"
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

func rotationConn(t *testing.T) *db.Connection {
	t.Helper()
	conn, err := db.NewConnection(t.Context())
	require.NoError(t, err)
	enc, err := kms.New(t.Context(), conn, "test-secret-0123456789-0123456789")
	require.NoError(t, err)
	require.NoError(t, crypto.SetEncryptor(enc))
	return conn
}

func seedCA(t *testing.T, conn *db.Connection, workspaceID string) *db.SSHCA {
	t.Helper()
	info, err := ssh.NewCA()
	require.NoError(t, err)
	info.Name = "ca-" + uuid.NewV7().String()
	var ca *db.SSHCA
	require.NoError(t, conn.TenantTx(pinned(t, workspaceID), func(q *db.Queries) (err error) {
		ca, err = q.CreateCA(t.Context(), info)
		return err
	}))
	return ca
}

func pinned(t *testing.T, workspaceID string) context.Context {
	t.Helper()
	return actor.WithWorkspace(t.Context(), actor.Workspace{ID: workspaceID})
}

func seedWorkspace(t *testing.T, conn *db.Connection) string {
	t.Helper()
	workspaceID := uuid.NewV7().String()
	require.NoError(t, conn.TenantTx(pinned(t, workspaceID), func(q *db.Queries) error {
		_, err := q.CreateWorkspace(t.Context(), &db.CreateWorkspaceParams{
			ID: workspaceID, Slug: uuid.NewV7().String(), Name: "rotate",
			Settings: &nokkuv1.WorkspaceSettings{},
		})
		return err
	}))
	return workspaceID
}

func TestRolloverKeepsOrRevokesPreviousKey(t *testing.T) {
	conn := rotationConn(t)
	ca := seedCA(t, conn, seedWorkspace(t, conn))

	rollover := func(revoke bool) *db.SSHCA {
		var next *db.SSHCA
		require.NoError(t, conn.SysTx(t.Context(), func(q *db.Queries) (err error) {
			current, err := q.GetCAForUpdate(t.Context(), ca.ID)
			if err != nil {
				return err
			}
			next, err = ssh.Rollover(t.Context(), q, current, revoke)
			return err
		}))
		return next
	}

	planned := rollover(false)
	assert.NotEqual(t, ca.PublicKey, planned.PublicKey)
	assert.NotEqual(t, ca.HostPublicKey, planned.HostPublicKey, "a rollover replaces both keys")
	assert.True(t, planned.RotatedAt.After(ca.RotatedAt), "the rotation time moves")
	require.NotNil(t, planned.PreviousPublicKey, "a planned rollover keeps the replaced key")
	assert.Equal(t, ca.PublicKey, *planned.PreviousPublicKey)
	require.NotNil(t, planned.PreviousHostPublicKey)
	assert.Equal(t, ca.HostPublicKey, *planned.PreviousHostPublicKey)
	require.NotNil(t, planned.PreviousTrustedUntil)
	assert.WithinDuration(t, time.Now().Add(planned.UserMaxTtl), *planned.PreviousTrustedUntil, time.Minute,
		"the replaced key is trusted for as long as its certificates can live")

	emergency := rollover(true)
	assert.NotEqual(t, planned.PublicKey, emergency.PublicKey)
	assert.Nil(t, emergency.PreviousPublicKey, "an emergency rollover trusts no older key")
	assert.Nil(t, emergency.PreviousHostPublicKey)
	assert.Nil(t, emergency.PreviousTrustedUntil)
}
