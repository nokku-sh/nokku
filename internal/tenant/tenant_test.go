package tenant

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
	"github.com/nokku-sh/nokku/internal/cache"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/crypto/kms"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/testdb"
)

func TestMain(m *testing.M) {
	testdb.Setup("tenant")
	os.Exit(m.Run())
}

func testConnection(t *testing.T) *db.Connection {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	c, err := db.NewConnection(ctx)
	if err != nil {
		t.Skipf("no test database: %v", err)
	}
	cipher, err := kms.New(ctx, c, "test-secret-0123456789-0123456789")
	require.NoError(t, err)
	require.NoError(t, crypto.SetEncryptor(cipher))
	return c
}

func TestFromHostParsesWithoutTheDatabase(t *testing.T) {
	r := &Resolver{saas: true, scheme: "https", host: "nokku.sh", slugs: cache.NewLocal[actor.Workspace](time.Minute)}
	cached := actor.Workspace{ID: "1", Slug: "acme", BaseURL: "https://acme.nokku.sh"}
	r.slugs.Put("acme", cached)

	root, err := r.FromHost(t.Context(), "nokku.sh")
	require.NoError(t, err)
	assert.Empty(t, root.ID, "the root host has no workspace")

	ws, err := r.FromHost(t.Context(), "ACME.nokku.sh:443")
	require.NoError(t, err)
	assert.Equal(t, cached, ws)

	for _, host := range []string{"app.nokku.sh", "a.b.nokku.sh", "evil.com", ".nokku.sh", "nokku.sh.evil.com"} {
		_, err := r.FromHost(t.Context(), host)
		assert.ErrorIs(t, err, ErrUnknownWorkspace, host)
	}
}

func TestBaseURL(t *testing.T) {
	saas := &Resolver{saas: true, scheme: "https", host: "nokku.sh"}
	assert.Equal(t, "https://acme.nokku.sh", saas.BaseURL("acme"))
	local := &Resolver{scheme: "http", host: "localhost", port: "3000"}
	assert.Equal(t, "http://localhost:3000", local.BaseURL("ignored"))
}

func TestSelfHostBootCreatesTheWorkspaceOnce(t *testing.T) {
	c := testConnection(t)
	t.Setenv("NOKKU_WORKSPACE_NAME", "Lab")
	// A self-hosted database is empty before its first boot. The other tests
	// leave workspaces behind and run in any order, so those go first. Only
	// the owner role deletes past RLS.
	owner, err := pgx.Connect(t.Context(), "")
	require.NoError(t, err)
	_, err = owner.Exec(t.Context(), "DELETE FROM workspaces")
	require.NoError(t, err)
	require.NoError(t, owner.Close(t.Context()))

	first, err := New(t.Context(), c, "http://localhost:3000", false)
	require.NoError(t, err)
	ws := first.Single()
	assert.Equal(t, "http://localhost:3000", ws.BaseURL)

	second, err := New(t.Context(), c, "http://localhost:3000", false)
	require.NoError(t, err)
	assert.Equal(t, ws.ID, second.Single().ID, "a second boot reuses the workspace")

	got, err := first.FromHost(t.Context(), "whatever.example")
	require.NoError(t, err)
	assert.Equal(t, ws.ID, got.ID, "self-host ignores the host")

	var cas int
	require.ErrorIs(t, c.Pool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM certificate_authorities WHERE workspace_id = $1 AND is_default`, ws.ID).Scan(&cas),
		db.ErrWorkspaceNotPinned, "nokku_app reaches nothing unpinned")
	require.NoError(t, c.WithWorkspace(actor.WithWorkspace(t.Context(), ws), func(q *db.Queries) error {
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
	r, err := New(t.Context(), c, "https://nokku.test", true)
	require.NoError(t, err)

	slug := "w" + uuid.New().String()[:8]
	created, err := Create(t.Context(), c, slug, "Acme")
	require.NoError(t, err)

	ws, err := r.FromHost(t.Context(), slug+".nokku.test")
	require.NoError(t, err)
	assert.Equal(t, created.ID, ws.ID)
	assert.Equal(t, "https://"+slug+".nokku.test", ws.BaseURL)

	_, err = r.FromHost(t.Context(), "nobody.nokku.test")
	assert.ErrorIs(t, err, ErrUnknownWorkspace)
}

func TestForbiddenSlugs(t *testing.T) {
	for _, slug := range []string{"www", "api", "google", "my-google-sso", "acme-login", "paypal-verify", "okta"} {
		assert.True(t, Forbidden(slug), slug)
	}
	for _, slug := range []string{"acme", "blue-sky", "w0rkshop", "default"} {
		assert.False(t, Forbidden(slug), slug)
	}
}

// A signup nobody ever signed in to frees its slug after a day.
func TestPurgeUnclaimed(t *testing.T) {
	c := testConnection(t)
	r, err := New(t.Context(), c, "https://nokku.test", true)
	require.NoError(t, err)

	slug := "w" + uuid.New().String()[:8]
	_, err = Create(t.Context(), c, slug, "Squat")
	require.NoError(t, err)
	_, err = r.FromHost(t.Context(), slug+".nokku.test")
	require.NoError(t, err, "the fresh signup resolves")

	require.NoError(t, r.PurgeUnclaimed(t.Context(), time.Now().Add(-time.Hour)), "too young to purge")
	_, err = r.FromHost(t.Context(), slug+".nokku.test")
	require.NoError(t, err)

	require.NoError(t, r.PurgeUnclaimed(t.Context(), time.Now().Add(time.Second)))
	_, err = r.FromHost(t.Context(), slug+".nokku.test")
	assert.ErrorIs(t, err, ErrUnknownWorkspace, "purged, and gone from the cache too")
}
