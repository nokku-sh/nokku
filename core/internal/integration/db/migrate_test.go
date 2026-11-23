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

// recover and rotate-secrets run next to the server. Opening must not migrate.
func TestNewConnectionChangesNothing(t *testing.T) {
	ctx := t.Context()
	owner, err := pgx.Connect(ctx, "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = owner.Close(context.WithoutCancel(ctx)) })

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
}

// A role that cannot log in has no password to set at a start, to read in a Postgres log or to share with a second
// database of the cluster.
func TestRuntimeRolesCannotLogIn(t *testing.T) {
	c := testConnection(t)
	rows, err := c.sysPool.Query(t.Context(), `
		SELECT rolname::TEXT, rolcanlogin FROM pg_roles WHERE rolname IN ('nokku_app', 'nokku_system')`)
	require.NoError(t, err)
	roles, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (string, error) {
		var name string
		var login bool
		err := row.Scan(&name, &login)
		assert.False(t, login, "%s can log in", name)
		return name, err
	})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"nokku_app", "nokku_system"}, roles)
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
