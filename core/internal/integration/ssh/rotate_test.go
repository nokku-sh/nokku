//go:build integration

package ssh_test

import (
	"context"
	"os"
	"sync"
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

const caLifetime = 365 * 24 * time.Hour

// seedCA stores a one year CA whose validity started age ago.
func seedCA(t *testing.T, conn *db.Connection, workspaceID string, age time.Duration) *db.SSHCA {
	t.Helper()
	info, err := ssh.NewCA(nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_ED25519, 0, caLifetime)
	require.NoError(t, err)
	notBefore := time.Now().Add(-age)
	info.Name = "ca-" + notBefore.Format(time.RFC3339Nano)
	info.NotBefore, info.NotAfter = notBefore, notBefore.Add(caLifetime)
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

func getCA(t *testing.T, conn *db.Connection, id string) *db.SSHCA {
	t.Helper()
	ca, err := conn.Sys().GetCA(t.Context(), id)
	require.NoError(t, err)
	return ca
}

func TestRotateExpiringDrainsEveryDueCA(t *testing.T) {
	conn := rotationConn(t)
	ws := seedWorkspace(t, conn)
	dueA := seedCA(t, conn, ws, 300*24*time.Hour)
	dueB := seedCA(t, conn, seedWorkspace(t, conn), 330*24*time.Hour)
	fresh := seedCA(t, conn, ws, 24*time.Hour)

	// Another instance holds dueC, the pass must skip it instead of waiting.
	dueC := seedCA(t, conn, ws, 320*24*time.Hour)
	locked, release := make(chan struct{}), make(chan struct{})
	var holder sync.WaitGroup
	holder.Go(func() {
		_ = conn.SysTx(context.WithoutCancel(t.Context()), func(q *db.Queries) error {
			if _, err := q.GetCAForUpdate(t.Context(), dueC.ID); err != nil {
				return err
			}
			close(locked)
			<-release
			return nil
		})
	})
	<-locked

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	ssh.RotateDue(ctx, conn)
	close(release)
	// The lock is only gone once the holder has committed.
	holder.Wait()
	require.NoError(t, ctx.Err(), "a pass must finish on its own")

	for _, ca := range []*db.SSHCA{dueA, dueB} {
		got := getCA(t, conn, ca.ID)
		assert.NotEqual(t, ca.PublicKey, got.PublicKey, "due CA %s was not rotated", ca.ID)
		assert.WithinDuration(t, time.Now(), got.NotBefore, time.Minute, "rotated CA starts now")
		assert.Equal(t, caLifetime, got.Lifetime, "rotation keeps the lifetime")
	}
	assert.Equal(t, fresh.PublicKey, getCA(t, conn, fresh.ID).PublicKey, "fresh CA must not rotate")
	assert.Equal(t, dueC.PublicKey, getCA(t, conn, dueC.ID).PublicKey, "locked CA belongs to the other instance")

	// The next pass picks the released CA up.
	ssh.RotateDue(t.Context(), conn)
	assert.NotEqual(t, dueC.PublicKey, getCA(t, conn, dueC.ID).PublicKey, "released CA rotates on the next pass")
}

func TestExpiringCAQuerySkipsFailed(t *testing.T) {
	conn := rotationConn(t)
	due := seedCA(t, conn, seedWorkspace(t, conn), 360*24*time.Hour)

	skip := []string{due.ID}
	require.NoError(t, conn.SysTx(t.Context(), func(q *db.Queries) error {
		for {
			ca, err := q.GetExpiringCAForUpdate(t.Context(), skip)
			if err != nil {
				return nil //nolint:nilerr // no rows left is the expected end
			}
			assert.NotEqual(t, due.ID, ca.ID, "a failed CA must not be picked again in the same pass")
			skip = append(skip, ca.ID)
		}
	}))
}

func TestRolloverKeepsOrRevokesPreviousKey(t *testing.T) {
	conn := rotationConn(t)
	ca := seedCA(t, conn, seedWorkspace(t, conn), 24*time.Hour)

	rollover := func(revoke bool) *db.SSHCA {
		var next *db.SSHCA
		require.NoError(t, conn.SysTx(t.Context(), func(q *db.Queries) (err error) {
			current, err := q.GetCAForUpdate(t.Context(), ca.ID)
			if err != nil {
				return err
			}
			next, err = ssh.Rollover(t.Context(), q, current, current.KeyType, current.KeyBits, revoke)
			return err
		}))
		return next
	}

	planned := rollover(false)
	require.NotNil(t, planned.PreviousPublicKey, "a planned rollover keeps the replaced key")
	assert.Equal(t, ca.PublicKey, *planned.PreviousPublicKey)
	require.NotNil(t, planned.PreviousTrustedUntil)
	assert.WithinDuration(t, time.Now().Add(planned.UserMaxTtl), *planned.PreviousTrustedUntil, time.Minute,
		"the replaced key is trusted for as long as its certificates can live")

	emergency := rollover(true)
	assert.NotEqual(t, planned.PublicKey, emergency.PublicKey)
	assert.Nil(t, emergency.PreviousPublicKey, "an emergency rollover trusts no older key")
	assert.Nil(t, emergency.PreviousTrustedUntil)
}
