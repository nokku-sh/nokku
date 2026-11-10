//go:build integration

package db_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	triggerInsert = 1 << 2
	triggerDelete = 1 << 3
	triggerUpdate = 1 << 4
)

// syncInputs hold the CA keys and idle timeout a sync reads as well.
var syncInputs = []string{"ssh_cas", "workspaces"}

// fixedColumns are read by the access view but no query updates them. Keys
// (id, workspace_id) are left out, nothing updates those.
var fixedColumns = map[string]string{
	"grants.account_id":         "a grant is deleted and made anew, never moved",
	"grants.user_id":            "a grant is deleted and made anew, never moved",
	"grants.team_id":            "a grant is deleted and made anew, never moved",
	"grants.service_account_id": "a grant is deleted and made anew, never moved",
	"grants.subject_id":         "generated from the subject columns",
	"grants.subject_kind":       "generated from the subject columns",
	"grants.created_at":         "set on insert",
	"target_accounts.target_id": "accounts are added and removed, never changed",
	"target_accounts.username":  "accounts are added and removed, never changed",
	"targets.daemon_id":         "a target's daemon never changes",
	"team_members.team_id":      "members are added and removed, never changed",
	"team_members.user_id":      "members are added and removed, never changed",
}

// syncColumns are read by a sync outside the access view.
var syncColumns = []string{
	"ssh_cas.public_key", "ssh_cas.host_public_key", "workspaces.settings", "daemons.status", "daemons.config",
}

// quietRows are tables of the view whose new or deleted rows need no trigger.
var quietRows = map[string]string{
	"users":           "a new person holds no grant, deleting one deletes its grants and memberships",
	"targets":         "a new target has no accounts, deleting one deletes its accounts",
	"target_accounts": "a new account holds no grant",
	"daemons":         "a new daemon's target holds no grant",
}

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// A change to who may log in where reaches daemons only through a
// notify_state_change trigger. Every table the answer is made of needs one.
func TestEveryAccessTableNotifies(t *testing.T) {
	ctx := t.Context()
	owner := ownerConn(t)

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
	_, err = tx.Exec(ctx, "DROP TRIGGER notify_state_change ON users")
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

// silent lists the tables of names with no notify_state_change trigger.
func silent(t *testing.T, q querier, names []string) []string {
	t.Helper()
	var out []string
	for _, name := range names {
		if notifyEvents(t, q, name) == 0 && !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out
}

// A table-level trigger is not enough: users had one, on another column, when
// a deactivated person kept host access (fdd48c2).
func TestEveryAccessColumnNotifies(t *testing.T) {
	ctx := t.Context()
	owner := ownerConn(t)

	columns := viewColumns(t, owner, "effective_access")
	require.Contains(t, columns, "grants.expires_at", "the walk found nothing, the view moved or was renamed")
	for column := range fixedColumns {
		assert.Contains(t, columns, column, "fixedColumns names %s, the view no longer reads it", column)
	}
	assert.Empty(
		t,
		unnotified(t, owner, append(columns, syncColumns...)),
		"these columns change access without telling a daemon, add them to a notify_state_change trigger",
	)

	tx, err := owner.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	_, err = tx.Exec(ctx, "DROP TRIGGER notify_state_change ON users")
	require.NoError(t, err)
	assert.Equal(t, []string{"users.active"}, unnotified(t, tx, columns))
}

func TestEveryAccessTableNotifiesOnInsertAndDelete(t *testing.T) {
	owner := ownerConn(t)

	tables := viewTables(t, owner, "effective_access")
	for table := range quietRows {
		assert.Contains(t, tables, table, "quietRows names %s, the view no longer reads it", table)
	}
	for _, table := range tables {
		if _, ok := quietRows[table]; ok {
			continue
		}
		events := notifyEvents(t, owner, table)
		assert.NotZero(t, events&triggerInsert, "%s: a new row can grant access, add a notify trigger on insert", table)
		assert.NotZero(
			t,
			events&triggerDelete,
			"%s: a deleted row can end access, add a notify trigger on delete",
			table,
		)
	}
}

// viewColumns lists the table columns a view reads, as table.column, through
// the views it reads.
func viewColumns(t *testing.T, q querier, view string) []string {
	t.Helper()
	rows, err := q.Query(t.Context(), `
		WITH RECURSIVE views (oid) AS (
			SELECT $1::regclass::oid
			UNION
			SELECT d.refobjid
			FROM views
				JOIN pg_rewrite r ON r.ev_class = views.oid
				JOIN pg_depend d ON d.classid = 'pg_rewrite'::regclass AND d.objid = r.oid
				JOIN pg_class c ON c.oid = d.refobjid AND c.relkind = 'v'
			WHERE d.refobjid <> r.ev_class
		)
		SELECT DISTINCT c.relname || '.' || a.attname
		FROM views
			JOIN pg_rewrite r ON r.ev_class = views.oid
			JOIN pg_depend d ON d.classid = 'pg_rewrite'::regclass AND d.objid = r.oid AND d.refobjsubid > 0
			JOIN pg_class c ON c.oid = d.refobjid AND c.relkind IN ('r', 'p')
			JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = d.refobjsubid
		ORDER BY 1`, view)
	require.NoError(t, err)
	columns, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	return columns
}

// unnotified lists the columns that no notify_state_change trigger fires on
// when they are updated, leaving out keys and fixedColumns.
func unnotified(t *testing.T, q querier, columns []string) []string {
	t.Helper()
	var out []string
	for _, column := range columns {
		table, name, _ := strings.Cut(column, ".")
		if _, ok := fixedColumns[column]; ok || name == "id" || name == "workspace_id" {
			continue
		}
		var notifies bool
		require.NoError(t, q.QueryRow(t.Context(), `
			SELECT EXISTS (
				SELECT 1 FROM pg_trigger t
				WHERE t.tgrelid = $1::regclass AND t.tgname LIKE 'notify_state_change%'
					AND t.tgtype & $3 <> 0 AND t.tgenabled <> 'D'
					AND (
						-- A WHEN may filter on another column, only a listed one counts then.
						(cardinality(t.tgattr::INT2[]) = 0 AND t.tgqual IS NULL)
						OR (SELECT attnum FROM pg_attribute WHERE attrelid = t.tgrelid AND attname = $2) = ANY (t.tgattr::INT2[])
					)
			)`, table, name, triggerUpdate).Scan(&notifies))
		if !notifies {
			out = append(out, column)
		}
	}
	return out
}

// notifyEvents ORs the event bits of a table's notify_state_change triggers.
func notifyEvents(t *testing.T, q querier, table string) int16 {
	t.Helper()
	var events int16
	require.NoError(t, q.QueryRow(t.Context(), `
		SELECT COALESCE(bit_or(tgtype), 0)::INT2 FROM pg_trigger
		WHERE tgrelid = $1::regclass AND tgname LIKE 'notify_state_change%' AND tgenabled <> 'D'`, table).Scan(&events))
	return events
}
