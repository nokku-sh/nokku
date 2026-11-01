//go:build integration

package db_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"uuid"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/integration/testenv"
)

// Tenant queries carry no workspace filter. These tests are what that rests on.

const tenantPolicy = "(workspace_id = current_workspace_id())"

// unscoped has a workspace_id but no policy, on purpose. Only definer triggers
// write these, the app role cannot.
var unscoped = []string{"workspace_state", "recording_deletes"}

// pinnedConn runs statements the way a request does: nokku_app, pinned to ws.
func pinnedConn(t *testing.T, c *conn, ws string) *pgx.Conn {
	t.Helper()
	// Leaving the pool pins it, see pinWorkspace.
	pooled, err := c.Pool.Acquire(testenv.Pinned(t, ws))
	require.NoError(t, err, "acquire")
	conn := pooled.Hijack()
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// seedEveryTable puts a row into each tenant table the fixture leaves empty.
func seedEveryTable(t *testing.T, c *conn, f stateFixture) {
	t.Helper()
	_, err := c.sysPool.Exec(t.Context(), `
		INSERT INTO credentials (id, workspace_id, user_id, type, data) VALUES ($2 || '-pk', $1, $2, 'passkey', 'x');
		INSERT INTO access_tokens (token_hash, workspace_id, user_id, kind, method)
		VALUES ($2 || '-s', $1, $2, 'user', 'passkey');
		INSERT INTO known_devices (workspace_id, user_id, key, expires_at)
		VALUES ($1, $2, 'cookie', NOW() + INTERVAL '1 day');
		INSERT INTO one_time_tokens (token_hash, workspace_id, user_id, purpose, expires_at)
		VALUES ($2 || '-ott', $1, $2, 'login', NOW() + INTERVAL '1 hour');
		INSERT INTO one_time_tokens (token_hash, workspace_id, purpose, email, role, expires_at)
		VALUES ($2 || '-inv', $1, 'invite', $2 || '@invite.test', 1, NOW() + INTERVAL '1 hour');
		INSERT INTO device_grants (device_code_hash, workspace_id, user_code, expires_at)
		VALUES ($2 || '-dg', $1, 'BCDF-GHJK', NOW() + INTERVAL '1 hour');
		INSERT INTO sso_providers (workspace_id, provider_id, config) VALUES ($1, 'idp', 'sealed');
		WITH sa AS (
			INSERT INTO service_accounts (workspace_id, name) VALUES ($1, 'ci') RETURNING id
		)
		INSERT INTO service_account_federations (workspace_id, service_account_id, issuer, claims)
		SELECT $1, id, 'https://ci.test', '{"sub": "job"}' FROM sa;
		WITH ca AS (
			SELECT id FROM ssh_cas WHERE workspace_id = $1
		)
		INSERT INTO ssh_ca_keys (ca_id, workspace_id, kind, private_key) SELECT id, $1, 'user', 'sealed' FROM ca;
		WITH t AS (
			INSERT INTO join_tokens (workspace_id, token_hash) VALUES ($1, $2 || '-jt') RETURNING id
		)
		INSERT INTO join_token_grants (workspace_id, token_id, username, user_id) SELECT $1, id, 'dev', $2 FROM t;
		INSERT INTO recordings (workspace_id, daemon_name, username, key) VALUES ($1, 'd', 'deploy', 'key');
		INSERT INTO workspace_subscriptions (workspace_id, source, plan) VALUES ($1, 'stripe', 'pro');
		INSERT INTO access_usage (workspace_id, target_id, subject_id) VALUES ($1, $3, $2);
		INSERT INTO access_requests (workspace_id, requester_id, account_id, duration, reason)
		VALUES ($1, $2, $4, '1 hour', 'fix');
		INSERT INTO audit_streams (workspace_id, kind, url, secret) VALUES ($1, 'webhook', 'https://siem.test', 'key');
	`, pgx.QueryExecModeSimpleProtocol, f.ws, f.u, f.target, f.account)
	require.NoError(t, err, "seed every table")
}

// tenantTables reads the catalog, so a table added later is covered too.
func tenantTables(t *testing.T, c *conn) []string {
	t.Helper()
	rows, err := c.sysPool.Query(t.Context(), `
		SELECT c.relname::TEXT
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'workspace_id' AND NOT a.attisdropped
		WHERE n.nspname = 'public' AND c.relkind = 'r'
		ORDER BY 1`)
	require.NoError(t, err, "list tenant tables")
	tables, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err, "list tenant tables")
	tables = slices.DeleteFunc(tables, func(name string) bool { return slices.Contains(unscoped, name) })
	require.NotEmpty(t, tables, "found no tenant tables")
	return tables
}

func count(t *testing.T, q db.DBTX, sql string, args ...any) int64 {
	t.Helper()
	var n int64
	require.NoError(t, q.QueryRow(t.Context(), sql, args...).Scan(&n), sql)
	return n
}

func pgCode(err error) string {
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok {
		return pgErr.Code
	}
	return ""
}

// A new tenant table without the policy or the default fails here, not in prod.
func TestEveryTenantTableHasThePolicy(t *testing.T) {
	c := testConnection(t)
	for _, table := range tenantTables(t, c) {
		var enabled, forced bool
		require.NoError(t, c.sysPool.QueryRow(t.Context(),
			`SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = ('public.' || $1)::regclass`,
			table).Scan(&enabled, &forced), table)
		assert.True(t, enabled, "%s: row security is not enabled", table)
		assert.True(t, forced, "%s: row security is not forced", table)

		type policy struct {
			Name      string
			Roles     []string
			Cmd       string
			Qual      *string
			WithCheck *string
		}
		rows, err := c.sysPool.Query(t.Context(), `
			SELECT policyname::TEXT, roles::TEXT[], cmd, qual, with_check
			FROM pg_policies WHERE schemaname = 'public' AND tablename = $1`, table)
		require.NoError(t, err, table)
		policies, err := pgx.CollectRows(rows, pgx.RowToStructByPos[policy])
		require.NoError(t, err, table)
		// One policy only. A second one would be OR-ed in and widen access.
		if !assert.Len(t, policies, 1, "%s: want the one tenant_isolation", table) {
			continue
		}
		p := policies[0]
		assert.Equal(t, "tenant_isolation", p.Name, table)
		assert.Equal(t, "ALL", p.Cmd, table)
		assert.Equal(t, []string{"nokku_app"}, p.Roles, table)
		const notThePin = "%s: policy does not compare workspace_id with the pinned workspace"
		assert.Equal(t, new(tenantPolicy), p.Qual, notThePin, table)
		assert.Equal(t, new(tenantPolicy), p.WithCheck, notThePin, table)

		var def *string
		var nullable string
		require.NoError(t, c.sysPool.QueryRow(t.Context(), `
			SELECT column_default, is_nullable FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = $1 AND column_name = 'workspace_id'`,
			table).Scan(&def, &nullable), table)
		const wantColumn = "%s: workspace_id must be NOT NULL DEFAULT current_workspace_id()"
		assert.Equal(t, new("current_workspace_id()"), def, wantColumn, table)
		assert.Equal(t, "NO", nullable, wantColumn, table)
	}
}

// The app role cannot bypass row security, or become the role that does.
func TestAppRoleIsSubjectToRowSecurity(t *testing.T) {
	c := testConnection(t)
	var name string
	var super, bypass, system bool
	f := newStateFixture(t, c)
	require.NoError(t, c.Pool.QueryRow(testenv.Pinned(t, f.ws), `
		SELECT rolname::TEXT, rolsuper, rolbypassrls, pg_has_role(rolname, 'nokku_system', 'MEMBER')
		FROM pg_roles WHERE rolname = current_user`,
	).Scan(&name, &super, &bypass, &system), "read role")
	require.Equal(t, "nokku_app", name, "the request pool runs as another role")
	require.False(t, super, "the request pool is a superuser")
	require.False(t, bypass, "the request pool has bypassrls")
	require.False(t, system, "the request pool is a member of nokku_system")
}

func TestWorkspaceReachesOnlyItsOwnRows(t *testing.T) {
	c := testConnection(t)
	a, b := newStateFixture(t, c), newStateFixture(t, c)
	seedEveryTable(t, c, a)
	seedEveryTable(t, c, b)
	asA := pinnedConn(t, c, a.ws)

	for _, table := range tenantTables(t, c) {
		name := pgx.Identifier{table}.Sanitize()
		own := count(t, c.sysPool, "SELECT COUNT(*) FROM "+name+" WHERE workspace_id = $1", a.ws)
		foreign := count(t, c.sysPool, "SELECT COUNT(*) FROM "+name+" WHERE workspace_id = $1", b.ws)
		const noRows = "%s: no rows to test with, seed one in seedEveryTable"
		if !assert.NotZero(t, own, noRows, table) || !assert.NotZero(t, foreign, noRows, table) {
			continue
		}
		assert.Equal(t, own, count(t, asA, "SELECT COUNT(*) FROM "+name), "%s: an unfiltered read", table)
		assert.Zero(t,
			count(t, asA, "SELECT COUNT(*) FROM "+name+" WHERE workspace_id = $1", b.ws),
			"%s: read rows of another workspace", table)
		tag, err := asA.Exec(
			t.Context(),
			"UPDATE "+name+" SET workspace_id = workspace_id WHERE workspace_id = $1",
			b.ws,
		)
		if assert.NoError(t, err, "%s: update", table) {
			assert.Zero(t, tag.RowsAffected(), "%s: updated rows of another workspace", table)
		}
		tag, err = asA.Exec(t.Context(), "DELETE FROM "+name+" WHERE workspace_id = $1", b.ws)
		if assert.NoError(t, err, "%s: delete", table) {
			assert.Zero(t, tag.RowsAffected(), "%s: deleted rows of another workspace", table)
		}
		assert.Equal(t, foreign,
			count(t, c.sysPool, "SELECT COUNT(*) FROM "+name+" WHERE workspace_id = $1", b.ws),
			"%s: the other workspace changed", table)
	}

	assert.EqualValues(t, 1, count(t, asA, "SELECT COUNT(*) FROM workspaces"), "workspaces: want only its own")
}

// The queries the handlers call, which no longer name the workspace.
func TestQueriesAreScopedByThePin(t *testing.T) {
	c := testConnection(t)
	a, b := newStateFixture(t, c), newStateFixture(t, c)
	seedEveryTable(t, c, a)
	seedEveryTable(t, c, b)

	asOwner(t, c, a, func(q *db.Queries) error {
		ctx := t.Context()
		ws, err := q.GetWorkspace(ctx)
		if assert.NoError(t, err, "GetWorkspace") {
			assert.Equal(t, a.ws, ws.ID, "GetWorkspace, want the pinned one")
		}
		owner, err := q.GetOwner(ctx)
		if assert.NoError(t, err, "GetOwner") {
			assert.Equal(t, a.owner, owner.ID, "GetOwner, want the pinned workspace's")
		}
		user, err := q.GetUser(ctx, a.u)
		if assert.NoError(t, err, "own user not visible") {
			assert.Equal(t, a.u, user.ID)
		}
		own, err := q.ListUserSessions(ctx, a.u)
		if assert.NoError(t, err, "own sessions") {
			assert.Len(t, own, 1, "own sessions")
		}
		foreign, err := q.ListUserSessions(ctx, b.u)
		if assert.NoError(t, err, "foreign sessions") {
			assert.Empty(t, foreign, "read a foreign session")
		}
		creds, err := q.ListUserCredentials(ctx, b.u)
		if assert.NoError(t, err, "foreign credentials") {
			assert.Empty(t, creds, "read a foreign credential")
		}
		providers, err := q.ListSSOProviders(ctx)
		if assert.NoError(t, err, "ListSSOProviders") && assert.Len(t, providers, 1, "ListSSOProviders") {
			assert.Equal(t, a.ws, providers[0].WorkspaceID, "ListSSOProviders, want the one of this workspace")
		}
		n, err := q.DeleteSubjectTokens(ctx, b.u)
		if assert.NoError(t, err, "DeleteSubjectTokens") {
			assert.Zero(t, n, "deleted foreign sessions")
		}
		_, foreignUser := q.GetUser(ctx, b.u)
		_, foreignTarget := q.GetTarget(ctx, b.target)
		_, unknownSession := q.GetAccessToken(ctx, "nope")
		for what, err := range map[string]error{
			"foreign user visible":   foreignUser,
			"foreign target visible": foreignTarget,
			"unknown session":        unknownSession,
		} {
			assert.ErrorIs(t, err, pgx.ErrNoRows, what)
		}
		return nil
	})
}

func TestInsertTakesThePinnedWorkspace(t *testing.T) {
	c := testConnection(t)
	a, b := newStateFixture(t, c), newStateFixture(t, c)
	asA := pinnedConn(t, c, a.ws)

	team, err := db.New(asA).CreateTeam(t.Context(), &db.CreateTeamParams{Name: "ops"})
	require.NoError(t, err, "CreateTeam")
	require.Equal(t, a.ws, team.WorkspaceID, "want a team of the pinned workspace")

	// Naming another workspace, or moving a row there, is refused.
	_, err = asA.Exec(t.Context(), `INSERT INTO teams (workspace_id, name) VALUES ($1, 'smuggled')`, b.ws)
	assert.Equal(t, pgerrcode.InsufficientPrivilege, pgCode(err), "insert into another workspace: %v", err)
	_, err = asA.Exec(t.Context(), `UPDATE teams SET workspace_id = $1 WHERE id = $2`, b.ws, team.ID)
	assert.Equal(t, pgerrcode.InsufficientPrivilege, pgCode(err), "move into another workspace: %v", err)

	// The composite keys keep a row from pointing across workspaces.
	_, err = asA.Exec(t.Context(), `INSERT INTO team_members (user_id, team_id) VALUES ($1, $2)`, b.u, team.ID)
	assert.Equal(t, pgerrcode.ForeignKeyViolation, pgCode(err), "team member of another workspace: %v", err)

	// A workspace row is only created under its own pin.
	second := uuid.NewV7().String()
	_, err = asA.Exec(t.Context(), `INSERT INTO workspaces (id, slug, name) VALUES ($1, $2, 'second')`, second, second)
	assert.Equal(t, pgerrcode.InsufficientPrivilege, pgCode(err), "second workspace from a pinned one: %v", err)

	// Without a pin the default is NULL. System code has to name the workspace.
	_, err = c.Sys().CreateTeam(t.Context(), &db.CreateTeamParams{Name: "nowhere"})
	assert.Equal(t, pgerrcode.NotNullViolation, pgCode(err), "unpinned insert: %v", err)
	_, err = db.New(c.Pool).CreateTeam(t.Context(), &db.CreateTeamParams{Name: "nowhere"})
	assert.Error(t, err, "the app role inserted a row without a pin")
}

// Nothing leaves the request pool without a workspace on the context.
func TestUnpinnedRequestFailsClosed(t *testing.T) {
	c := testConnection(t)
	_, statement := c.Tenant().GetOwner(t.Context())
	for what, err := range map[string]error{
		"transaction":      c.TenantTx(t.Context(), func(*db.Queries) error { return nil }),
		"single statement": statement,
		"raw query":        c.Pool.QueryRow(t.Context(), "SELECT 1").Scan(new(int)),
	} {
		assert.ErrorIs(t, err, db.ErrWorkspaceNotPinned, what)
	}
}

// The pin is set each time a connection leaves the pool. A pool of one forces
// every call onto the same connection.
func TestPinFollowsTheContext(t *testing.T) {
	t.Setenv("NOKKU_DB_MAX_CONNS", "1")
	c := testConnection(t)
	a, b := newStateFixture(t, c), newStateFixture(t, c)

	for round := range 3 {
		for _, f := range []stateFixture{a, b} {
			ws, err := c.Tenant().GetWorkspace(testenv.Pinned(t, f.ws))
			require.NoError(t, err, "round %d: GetWorkspace", round)
			require.Equal(t, f.ws, ws.ID, "round %d: GetWorkspace", round)
			owner, err := c.Tenant().GetOwner(testenv.Pinned(t, f.ws))
			require.NoError(t, err, "round %d: GetOwner", round)
			require.Equal(t, f.owner, owner.ID, "round %d: GetOwner", round)
		}
		// The connection still carries b's pin here. It must not be usable.
		_, err := c.Tenant().GetOwner(t.Context())
		require.ErrorIs(t, err, db.ErrWorkspaceNotPinned, "round %d: unpinned read after a pinned one", round)
	}
	// A transaction is pinned the same way.
	asOwner(t, c, a, func(q *db.Queries) error {
		owner, err := q.GetOwner(t.Context())
		if err != nil {
			return err
		}
		assert.Equal(t, a.owner, owner.ID, "transaction saw the owner of another workspace")
		return nil
	})
}

// Requests of two workspaces share a small pool. Each sees only its own.
func TestPinHoldsUnderConcurrency(t *testing.T) {
	t.Setenv("NOKKU_DB_MAX_CONNS", "3")
	c := testConnection(t)
	fixtures := []stateFixture{newStateFixture(t, c), newStateFixture(t, c)}

	var wg sync.WaitGroup
	for worker := range 16 {
		wg.Go(func() {
			f := fixtures[worker%2]
			ctx := testenv.Pinned(t, f.ws)
			for range 40 {
				owner, err := c.Tenant().GetOwner(ctx)
				if err != nil || owner.ID != f.owner {
					t.Errorf("single statement: owner = %v, %v, want %s", owner, err, f.owner)
					return
				}
				err = c.TenantTx(ctx, func(q *db.Queries) error {
					ws, err := q.GetWorkspace(ctx)
					if err == nil && ws.ID != f.ws {
						t.Errorf("transaction: workspace %s, want %s", ws.ID, f.ws)
					}
					return err
				})
				if err != nil {
					t.Errorf("transaction: %v", err)
					return
				}
			}
		})
	}
	wg.Wait()
}

// A system connection is never pinned, so an insert that names no workspace
// fails even right after pinned traffic.
func TestSystemConnectionsStayUnpinned(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	_, err := c.Tenant().GetOwner(testenv.Pinned(t, f.ws))
	require.NoError(t, err, "pinned read")
	for range 8 {
		_, err := c.Sys().CreateTeam(testenv.Pinned(t, f.ws), &db.CreateTeamParams{Name: "nowhere"})
		require.Equal(t, pgerrcode.NotNullViolation, pgCode(err), "system insert without a workspace: %v", err)
	}
}

// One read of the pinned workspace, in a transaction and off the pool hook.
func BenchmarkSingleRead(b *testing.B) {
	c := testConnection(b)
	id := uuid.NewV7().String()
	_, err := c.sysPool.Exec(b.Context(), `INSERT INTO workspaces (id, slug, name) VALUES ($1, $2, 'bench')`, id, id)
	require.NoError(b, err, "seed")
	ctx := actor.WithWorkspace(b.Context(), actor.Workspace{ID: id})

	b.Run("transaction", func(b *testing.B) {
		for b.Loop() {
			require.NoError(b, c.TenantTx(ctx, func(q *db.Queries) error {
				_, err := q.GetWorkspace(ctx)
				return err
			}))
		}
	})
	b.Run("direct", func(b *testing.B) {
		for b.Loop() {
			_, err := c.Tenant().GetWorkspace(ctx)
			require.NoError(b, err)
		}
	})
}

// The system role is the one way around row security, see Connection.SysTx.
func TestSystemRoleSeesEveryWorkspace(t *testing.T) {
	c := testConnection(t)
	a, b := newStateFixture(t, c), newStateFixture(t, c)
	require.EqualValues(t, 4,
		count(t, c.sysPool, "SELECT COUNT(*) FROM users WHERE workspace_id = ANY ($1)", []string{a.ws, b.ws}),
		"the users of the two fixtures")
}

// The app role holds no DELETE on the audit table. The trigger refuses the
// system role outside the retention job.
func TestAuditLogIsAppendOnly(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	require.NoError(t, c.Tenant().InsertAuditLog(testenv.Pinned(t, f.ws), &db.InsertAuditLogParams{
		WorkspaceID: f.ws, Action: "Test", Ok: true, Details: []byte("{}"),
	}), "insert")

	const del = "DELETE FROM audit.audit_logs WHERE workspace_id = $1"
	_, err := c.Pool.Exec(testenv.Pinned(t, f.ws), del, f.ws)
	assert.Equal(t, pgerrcode.InsufficientPrivilege, pgCode(err), "app role delete: %v", err)
	_, err = c.sysPool.Exec(t.Context(), del, f.ws)
	assert.Error(t, err, "system role deleted an audit row without opting in")
}

// The app role writes events into the pinned workspace, and only there. No
// path writes them past RLS.
func TestAuditWritesStayInTheirWorkspace(t *testing.T) {
	c := testConnection(t)
	a, b := newStateFixture(t, c), newStateFixture(t, c)
	write := func(ctx context.Context, q *db.Queries, ws string) error {
		return q.InsertAuditLog(ctx, &db.InsertAuditLogParams{
			WorkspaceID: ws, Action: "Test", ActorKind: "user", Details: []byte("{}"),
		})
	}

	require.NoError(t, write(testenv.Pinned(t, a.ws), c.Tenant(), a.ws),
		"the app role could not write its own workspace's event")
	err := write(testenv.Pinned(t, a.ws), c.Tenant(), b.ws)
	assert.Equal(t, pgerrcode.InsufficientPrivilege, pgCode(err), "an event for another workspace: %v", err)
	err = write(t.Context(), c.Sys(), a.ws)
	assert.Equal(t, pgerrcode.InsufficientPrivilege, pgCode(err), "the system role wrote an event: %v", err)
}

func TestAuditLogScopes(t *testing.T) {
	c := testConnection(t)
	a, b := newStateFixture(t, c), newStateFixture(t, c)
	for _, row := range []struct{ ws, actor string }{{a.ws, a.u}, {b.ws, b.u}, {b.ws, b.owner}} {
		require.NoError(t, c.Tenant().InsertAuditLog(testenv.Pinned(t, row.ws), &db.InsertAuditLogParams{
			WorkspaceID: row.ws, ActorID: row.actor, Action: "Test", Ok: true, Details: []byte("{}"),
		}), "insert")
	}

	list := func(ws string) int {
		t.Helper()
		var rows []*db.ListAuditLogsRow
		require.NoError(t, c.TenantTx(testenv.Pinned(t, ws), func(q *db.Queries) (err error) {
			rows, err = q.ListAuditLogs(t.Context(), &db.ListAuditLogsParams{Limit: 100})
			return err
		}), "list")
		return len(rows)
	}
	assert.Equal(t, 1, list(a.ws), "workspace a")
	assert.Equal(t, 2, list(b.ws), "workspace b")

	_, err := c.sysPool.Exec(t.Context(), "DELETE FROM workspaces WHERE id = $1", a.ws)
	require.NoError(t, err, "delete workspace with audit rows")
}
