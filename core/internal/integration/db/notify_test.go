//go:build integration

package db_test

import (
	"context"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// syncInputs hold the CA keys and idle timeout a sync reads as well.
var syncInputs = []string{"ssh_cas", "workspaces"}

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// A change to who may log in where reaches daemons only through a
// bump_state_version trigger. Every table the answer is made of needs one.
func TestEveryAccessTableNotifies(t *testing.T) {
	ctx := t.Context()
	owner, err := pgx.Connect(ctx, "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = owner.Close(context.WithoutCancel(ctx)) })

	tables := viewTables(t, owner, "effective_access")
	require.Contains(t, tables, "grants", "the walk found nothing, the view moved or was renamed")
	// A target's daemon never changes, deleting a target deletes its accounts.
	tables = slices.DeleteFunc(tables, func(name string) bool { return name == "targets" })
	assert.NotContains(t, tables, "teams", "teams have no trigger, the view must reach them through team_members")
	assert.NotContains(t, tables, "service_accounts", "service accounts have no trigger")
	assert.Empty(
		t,
		silent(t, owner, append(tables, syncInputs...)),
		"these tables change access without telling a daemon",
	)

	// Without the trigger on users, a deactivated person keeps logging in.
	tx, err := owner.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	_, err = tx.Exec(ctx, "DROP TRIGGER bump_state_version ON users")
	require.NoError(t, err)
	assert.Equal(t, []string{"users"}, silent(t, tx, tables))
}

// viewTables lists the tables a view reads, through the views it reads.
func viewTables(t *testing.T, q querier, view string) []string {
	t.Helper()
	rows, err := q.Query(t.Context(), `
		WITH RECURSIVE deps (oid) AS (
			SELECT $1::regclass::oid
			UNION
			SELECT d.refobjid
			FROM deps
				JOIN pg_rewrite r ON r.ev_class = deps.oid
				JOIN pg_depend d ON d.classid = 'pg_rewrite'::regclass AND d.objid = r.oid
			WHERE d.refclassid = 'pg_class'::regclass AND d.refobjid <> r.ev_class
		)
		SELECT c.relname FROM deps JOIN pg_class c ON c.oid = deps.oid
		WHERE c.relkind IN ('r', 'p') ORDER BY 1`, view)
	require.NoError(t, err)
	tables, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	return tables
}

// silent lists the tables of names with no bump_state_version trigger.
func silent(t *testing.T, q querier, names []string) []string {
	t.Helper()
	var out []string
	for _, name := range names {
		var notifies bool
		require.NoError(t, q.QueryRow(
			t.Context(),
			`SELECT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = $1::regclass AND tgname LIKE 'bump_state_version%')`,
			name,
		).Scan(&notifies))
		if !notifies && !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out
}
