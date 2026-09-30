package pki

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/ssh"
	"github.com/nokku-sh/nokku/internal/testdb"
)

func TestMain(m *testing.M) {
	testdb.Setup("pki")
	os.Exit(m.Run())
}

func rotationConn(t *testing.T) *db.Connection {
	t.Helper()
	conn, err := db.NewConnection(t.Context())
	if err != nil {
		t.Skipf("no test database: %v", err)
	}
	box, err := crypto.NewSecretbox([]byte("test-secret"))
	require.NoError(t, err)
	require.NoError(t, crypto.SetEncryptor(box))
	return conn
}

const caLifetime = 365 * 24 * time.Hour

// seedCA stores a one year CA whose validity started age ago.
func seedCA(t *testing.T, conn *db.Connection, workspaceID string, age time.Duration) *db.CertificateAuthority {
	t.Helper()
	info, err := ssh.NewCA(nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_ED25519, 0, caLifetime)
	require.NoError(t, err)
	notBefore := time.Now().Add(-age)
	var ca *db.CertificateAuthority
	require.NoError(t, conn.WithTx(t.Context(), func(q *db.Queries) (err error) {
		ca, err = q.CreateCA(t.Context(), &db.CreateCAParams{
			WorkspaceID:  workspaceID,
			Name:         "ca-" + notBefore.Format(time.RFC3339Nano),
			Certificate:  string(info.Certificate),
			PrivateKey:   info.PrivateKey,
			PublicKey:    info.PublicKey,
			SerialNumber: info.SerialNumber,
			Subject:      info.Subject,
			NotBefore:    notBefore,
			NotAfter:     notBefore.Add(caLifetime),
			Lifetime:     caLifetime,
		})
		return err
	}))
	return ca
}

func seedWorkspace(t *testing.T, conn *db.Connection) string {
	t.Helper()
	var workspaceID string
	require.NoError(t, conn.WithTx(t.Context(), func(q *db.Queries) error {
		u, err := q.CreateUser(t.Context(), &db.CreateUserParams{
			Email: time.Now().Format("20060102150405.000000000") + "@rotate.test",
			Name:  "owner",
		})
		if err != nil {
			return err
		}
		ws, err := q.CreateWorkspace(t.Context(), &db.CreateWorkspaceParams{Name: "rotate", CreatedBy: u.ID})
		workspaceID = ws.ID
		return err
	}))
	return workspaceID
}

func getCA(t *testing.T, conn *db.Connection, id string) *db.CertificateAuthority {
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
	go func() {
		_ = conn.WithTx(context.WithoutCancel(t.Context()), func(q *db.Queries) error {
			if _, err := q.GetCAForUpdate(t.Context(), dueC.ID); err != nil {
				return err
			}
			close(locked)
			<-release
			return nil
		})
	}()
	<-locked

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	rotateExpiring(ctx, conn)
	close(release)
	require.NoError(t, ctx.Err(), "a pass must finish on its own")

	for _, ca := range []*db.CertificateAuthority{dueA, dueB} {
		got := getCA(t, conn, ca.ID)
		assert.NotEqual(t, ca.SerialNumber, got.SerialNumber, "due CA %s was not rotated", ca.ID)
		assert.WithinDuration(t, time.Now(), got.NotBefore, time.Minute, "rotated CA starts now")
		assert.Equal(t, caLifetime, got.Lifetime, "rotation keeps the lifetime")
	}
	assert.Equal(t, fresh.SerialNumber, getCA(t, conn, fresh.ID).SerialNumber, "fresh CA must not rotate")
	assert.Equal(t, dueC.SerialNumber, getCA(t, conn, dueC.ID).SerialNumber, "locked CA belongs to the other instance")

	// The next pass picks the released CA up.
	rotateExpiring(t.Context(), conn)
	assert.NotEqual(t, dueC.SerialNumber, getCA(t, conn, dueC.ID).SerialNumber, "released CA rotates on the next pass")
}

func TestExpiringCAQuerySkipsFailed(t *testing.T) {
	conn := rotationConn(t)
	due := seedCA(t, conn, seedWorkspace(t, conn), 360*24*time.Hour)

	skip := []string{due.ID}
	require.NoError(t, conn.WithTx(t.Context(), func(q *db.Queries) error {
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
