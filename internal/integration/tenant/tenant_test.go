//go:build integration

package tenant_test

import (
	"context"
	"os"
	"testing"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/crypto/kms"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/integration/testenv"
	"github.com/nokku-sh/nokku/internal/tenant"
)

func TestMain(m *testing.M) {
	stop := testenv.Postgres()
	code := m.Run()
	stop()
	os.Exit(code)
}

func testConnection(t *testing.T) *db.Connection {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	c, err := db.NewConnection(ctx)
	require.NoError(t, err)
	cipher, err := kms.New(ctx, c, "test-secret-0123456789-0123456789")
	require.NoError(t, err)
	require.NoError(t, crypto.SetEncryptor(cipher))
	return c
}

func TestSelfHostBootCreatesTheWorkspaceOnce(t *testing.T) {
	c := testConnection(t)
	t.Setenv("NOKKU_WORKSPACE_NAME", "Lab")
	// A self-hosted database is empty before its first boot, so workspaces of other tests go first.
	owner, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	_, err = owner.Exec(t.Context(), "DELETE FROM workspaces")
	require.NoError(t, err)
	require.NoError(t, owner.Close(t.Context()))

	first, err := tenant.New(t.Context(), c, "http://localhost:3000", false)
	require.NoError(t, err)
	ws := first.Single()
	assert.Equal(t, "http://localhost:3000", ws.BaseURL)

	second, err := tenant.New(t.Context(), c, "http://localhost:3000", false)
	require.NoError(t, err)
	assert.Equal(t, ws.ID, second.Single().ID, "a second boot reuses the workspace")

	got, err := first.FromHost(t.Context(), "whatever.example")
	require.NoError(t, err)
	assert.Equal(t, ws.ID, got.ID, "self-host ignores the host")

	var cas int
	require.ErrorIs(t, c.Pool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM ssh_cas WHERE workspace_id = $1 AND is_default`, ws.ID).Scan(&cas),
		db.ErrWorkspaceNotPinned, "nokku_app reaches nothing unpinned")
	require.NoError(t, c.TenantTx(actor.WithWorkspace(t.Context(), ws), func(q *db.Queries) error {
		row, err := q.GetWorkspace(t.Context())
		if err != nil {
			return err
		}
		assert.Equal(t, "Lab", row.Name)
		rows, err := q.ListCAs(t.Context(), &db.ListCAsParams{})
		if err != nil {
			return err
		}
		assert.Len(t, rows, 1, "boot made the default CA")
		return nil
	}))
}

func TestSaaSResolvesBySlug(t *testing.T) {
	c := testConnection(t)
	r, err := tenant.New(t.Context(), c, "https://nokku.test", true)
	require.NoError(t, err)

	slug := "w" + uuid.New().String()[:8]
	created, err := tenant.Create(t.Context(), c, slug, "Acme")
	require.NoError(t, err)

	ws, err := r.FromHost(t.Context(), slug+".nokku.test")
	require.NoError(t, err)
	assert.Equal(t, created.ID, ws.ID)
	assert.Equal(t, "https://"+slug+".nokku.test", ws.BaseURL)

	_, err = r.FromHost(t.Context(), "nobody.nokku.test")
	assert.ErrorIs(t, err, tenant.ErrUnknownWorkspace)
}

// A signup nobody ever signed in to frees its slug after a day.
func TestPurgeUnclaimed(t *testing.T) {
	c := testConnection(t)
	r, err := tenant.New(t.Context(), c, "https://nokku.test", true)
	require.NoError(t, err)

	slug := "w" + uuid.New().String()[:8]
	_, err = tenant.Create(t.Context(), c, slug, "Squat")
	require.NoError(t, err)
	_, err = r.FromHost(t.Context(), slug+".nokku.test")
	require.NoError(t, err, "the fresh signup resolves")

	require.NoError(t, r.PurgeUnclaimed(t.Context(), time.Now().Add(-time.Hour)), "too young to purge")
	_, err = r.FromHost(t.Context(), slug+".nokku.test")
	require.NoError(t, err)

	require.NoError(t, r.PurgeUnclaimed(t.Context(), time.Now().Add(time.Second)))
	_, err = r.FromHost(t.Context(), slug+".nokku.test")
	assert.ErrorIs(t, err, tenant.ErrUnknownWorkspace, "purged, and gone from the cache too")
}
