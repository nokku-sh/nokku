//go:build integration

package db_test

import (
	"context"
	"testing"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/db"
)

// admin-link and rotate-secrets run next to the server. Opening must not
// migrate or reset the role passwords.
func TestNewConnectionChangesNothing(t *testing.T) {
	ctx := t.Context()
	owner, err := pgx.Connect(ctx, "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = owner.Close(context.WithoutCancel(ctx)) })
	// The hash is salted, so setting the same password again still changes it.
	password := func() string {
		var p string
		require.NoError(
			t,
			owner.QueryRow(ctx, "SELECT rolpassword FROM pg_authid WHERE rolname = 'nokku_app'").Scan(&p),
		)
		return p
	}
	before := password()

	_, err = owner.Exec(ctx, "CREATE DATABASE nokku_open_only")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = owner.Exec(context.WithoutCancel(ctx), "DROP DATABASE nokku_open_only WITH (FORCE)")
	})
	t.Setenv("PGDATABASE", "nokku_open_only")

	_, err = db.NewConnection(ctx)
	require.NoError(t, err)

	fresh, err := pgx.Connect(ctx, "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = fresh.Close(context.WithoutCancel(ctx)) })
	var migrated bool
	require.NoError(t, fresh.QueryRow(ctx, "SELECT to_regclass('public.schema_version') IS NOT NULL").Scan(&migrated))
	assert.False(t, migrated, "opening a connection migrated the database")
	assert.Equal(t, before, password(), "opening a connection reset the role password")
}

// Only the owner migrates. A runtime role moving it breaks the next start.
func TestRuntimeRolesCannotTouchTheSchemaVersion(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	for name, run := range map[string]func(string) error{
		"nokku_app": func(sql string) error {
			_, err := pinnedConn(t, c, f.ws).Exec(t.Context(), sql)
			return err
		},
		"nokku_system": func(sql string) error {
			_, err := c.sysPool.Exec(t.Context(), sql)
			return err
		},
	} {
		assert.Equal(
			t,
			pgerrcode.InsufficientPrivilege,
			pgCode(run("UPDATE public.schema_version SET version = version")),
			"%s updated the schema version",
			name,
		)
	}
}
