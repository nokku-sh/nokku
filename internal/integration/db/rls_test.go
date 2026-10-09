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

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/db"
)

// Tenant queries carry no workspace filter. These tests are what that rests on.

// unscoped has a workspace_id but no policy, on purpose. It holds a counter the app role cannot write.
var unscoped = []string{"workspace_state"}

const tenantPolicy = "(workspace_id = current_workspace_id())"

func pinned(t *testing.T, ws string) context.Context {
	t.Helper()
	return actor.WithWorkspace(t.Context(), actor.Workspace{ID: ws})
}

// pinnedConn runs single statements the way a request does: nokku_app, pinned to ws.
func pinnedConn(t *testing.T, c *conn, ws string) *pgx.Conn {
	t.Helper()
	// Leaving the pool pins it, see pinWorkspace.
	pooled, err := c.Pool.Acquire(pinned(t, ws))
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	conn := pooled.Hijack()
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// seedEveryTable puts a row into each tenant table the fixture itself leaves empty.
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
		INSERT INTO sso_providers (workspace_id, provider_id) VALUES ($1, 'idp');
		INSERT INTO service_accounts (workspace_id, name) VALUES ($1, 'ci');
		INSERT INTO ssh_cas (workspace_id, name, private_key, public_key, not_before, not_after, key_bits)
		VALUES ($1, 'ca', 'key', 'pub', NOW(), NOW() + INTERVAL '1 day', 256);
		INSERT INTO join_tokens (id, workspace_id, kind, token_hash) VALUES (uuidv7(), $1, 1, 'hash');
		INSERT INTO recordings (workspace_id, daemon_name, username, key) VALUES ($1, 'd', 'deploy', 'key');
		INSERT INTO workspace_subscriptions (workspace_id) VALUES ($1);
	`, pgx.QueryExecModeSimpleProtocol, f.ws, f.u)
	if err != nil {
		t.Fatalf("seed every table: %v", err)
	}
}

// tenantTables reads the catalog, so a table added later is covered without a change here.
func tenantTables(t *testing.T, c *conn) []string {
	t.Helper()
	rows, err := c.sysPool.Query(t.Context(), `
		SELECT c.relname::TEXT
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'workspace_id' AND NOT a.attisdropped
		WHERE n.nspname = 'public' AND c.relkind = 'r'
		ORDER BY 1`)
	if err != nil {
		t.Fatalf("list tenant tables: %v", err)
	}
	tables, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatalf("list tenant tables: %v", err)
	}
	tables = slices.DeleteFunc(tables, func(name string) bool { return slices.Contains(unscoped, name) })
	if len(tables) == 0 {
		t.Fatal("found no tenant tables")
	}
	return tables
}

func count(t *testing.T, q db.DBTX, sql string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := q.QueryRow(t.Context(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func pgCode(err error) string {
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok {
		return pgErr.Code
	}
	return ""
}

// A new tenant table that misses the policy or the default fails here, not in production.
func TestEveryTenantTableHasThePolicy(t *testing.T) {
	c := testConnection(t)
	for _, table := range tenantTables(t, c) {
		var enabled, forced bool
		if err := c.sysPool.QueryRow(t.Context(),
			`SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = ('public.' || $1)::regclass`,
			table).Scan(&enabled, &forced); err != nil {
			t.Fatalf("%s: %v", table, err)
		}
		if !enabled || !forced {
			t.Errorf("%s: row security enabled=%v forced=%v, want both", table, enabled, forced)
		}

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
		if err != nil {
			t.Fatalf("%s: %v", table, err)
		}
		policies, err := pgx.CollectRows(rows, pgx.RowToStructByPos[policy])
		if err != nil {
			t.Fatalf("%s: %v", table, err)
		}
		// One policy only. A second one would be OR-ed in and widen access.
		if len(policies) != 1 {
			t.Errorf("%s: %d policies, want the one tenant_isolation", table, len(policies))
			continue
		}
		p := policies[0]
		if p.Name != "tenant_isolation" || p.Cmd != "ALL" || !slices.Equal(p.Roles, []string{"nokku_app"}) {
			t.Errorf("%s: policy %s for %v on %s, want tenant_isolation for nokku_app on ALL",
				table, p.Name, p.Roles, p.Cmd)
		}
		if p.Qual == nil || *p.Qual != tenantPolicy || p.WithCheck == nil || *p.WithCheck != tenantPolicy {
			t.Errorf("%s: policy does not compare workspace_id with the pinned workspace", table)
		}

		var def *string
		var nullable string
		if err := c.sysPool.QueryRow(t.Context(), `
			SELECT column_default, is_nullable FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = $1 AND column_name = 'workspace_id'`,
			table).Scan(&def, &nullable); err != nil {
			t.Fatalf("%s: %v", table, err)
		}
		if def == nil || *def != "current_workspace_id()" || nullable != "NO" {
			t.Errorf("%s: workspace_id must be NOT NULL DEFAULT current_workspace_id()", table)
		}
	}
}

// The app role cannot bypass row security on its own, and it cannot become the role that does.
func TestAppRoleIsSubjectToRowSecurity(t *testing.T) {
	c := testConnection(t)
	var name string
	var super, bypass, system bool
	f := newStateFixture(t, c)
	if err := c.Pool.QueryRow(pinned(t, f.ws), `
		SELECT rolname::TEXT, rolsuper, rolbypassrls, pg_has_role(rolname, 'nokku_system', 'MEMBER')
		FROM pg_roles WHERE rolname = current_user`,
	).Scan(&name, &super, &bypass, &system); err != nil {
		t.Fatalf("read role: %v", err)
	}
	if name != "nokku_app" || super || bypass || system {
		t.Fatalf("request pool runs as %s (super=%v, bypassrls=%v, member of nokku_system=%v), want plain nokku_app",
			name, super, bypass, system)
	}
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
		if own == 0 || foreign == 0 {
			t.Errorf("%s: no rows to test with, seed one in seedEveryTable", table)
			continue
		}
		if got := count(t, asA, "SELECT COUNT(*) FROM "+name); got != own {
			t.Errorf("%s: an unfiltered read sees %d rows, want its own %d", table, got, own)
		}
		if got := count(t, asA, "SELECT COUNT(*) FROM "+name+" WHERE workspace_id = $1", b.ws); got != 0 {
			t.Errorf("%s: read %d rows of another workspace", table, got)
		}
		tag, err := asA.Exec(
			t.Context(),
			"UPDATE "+name+" SET workspace_id = workspace_id WHERE workspace_id = $1",
			b.ws,
		)
		if err != nil || tag.RowsAffected() != 0 {
			t.Errorf("%s: updated %d rows of another workspace, err %v", table, tag.RowsAffected(), err)
		}
		tag, err = asA.Exec(t.Context(), "DELETE FROM "+name+" WHERE workspace_id = $1", b.ws)
		if err != nil || tag.RowsAffected() != 0 {
			t.Errorf("%s: deleted %d rows of another workspace, err %v", table, tag.RowsAffected(), err)
		}
		if got := count(t, c.sysPool, "SELECT COUNT(*) FROM "+name+" WHERE workspace_id = $1", b.ws); got != foreign {
			t.Errorf("%s: the other workspace went from %d to %d rows", table, foreign, got)
		}
	}

	if got := count(t, asA, "SELECT COUNT(*) FROM workspaces"); got != 1 {
		t.Errorf("workspaces: sees %d, want only its own", got)
	}
}

// The queries the handlers call, which no longer name the workspace.
func TestQueriesAreScopedByThePin(t *testing.T) {
	c := testConnection(t)
	a, b := newStateFixture(t, c), newStateFixture(t, c)
	seedEveryTable(t, c, a)
	seedEveryTable(t, c, b)

	asOwner(t, c, a, func(q *db.Queries) error {
		ctx := t.Context()
		if ws, err := q.GetWorkspace(ctx); err != nil || ws.ID != a.ws {
			t.Errorf("GetWorkspace = %v, %v, want the pinned one", ws, err)
		}
		if owner, err := q.GetOwner(ctx); err != nil || owner.ID != a.owner {
			t.Errorf("GetOwner = %v, %v, want the pinned workspace's", owner, err)
		}
		if _, err := q.GetUser(ctx, a.u); err != nil {
			t.Errorf("own user not visible: %v", err)
		}
		if _, err := q.GetUser(ctx, b.u); !errors.Is(err, pgx.ErrNoRows) {
			t.Errorf("foreign user visible: %v", err)
		}
		if _, err := q.GetTarget(ctx, b.target); !errors.Is(err, pgx.ErrNoRows) {
			t.Errorf("foreign target visible: %v", err)
		}
		if _, err := q.GetAccessToken(ctx, "nope"); !errors.Is(err, pgx.ErrNoRows) {
			t.Errorf("unknown session: %v", err)
		}
		own, err := q.ListUserSessions(ctx, a.u)
		if err != nil || len(own) != 1 {
			t.Errorf("own sessions: %d rows, err %v", len(own), err)
		}
		foreign, err := q.ListUserSessions(ctx, b.u)
		if err != nil || len(foreign) != 0 {
			t.Errorf("read a foreign session: %d rows, err %v", len(foreign), err)
		}
		creds, err := q.ListUserCredentials(ctx, b.u)
		if err != nil || len(creds) != 0 {
			t.Errorf("read a foreign credential: %d rows, err %v", len(creds), err)
		}
		providers, err := q.ListSSOProviders(ctx)
		if err != nil || len(providers) != 1 || providers[0].WorkspaceID != a.ws {
			t.Errorf("ListSSOProviders: %d rows, err %v, want the one of this workspace", len(providers), err)
		}
		if n, err := q.DeleteSubjectTokens(ctx, b.u); err != nil || n != 0 {
			t.Errorf("deleted %d foreign sessions, err %v", n, err)
		}
		return nil
	})
}

func TestInsertTakesThePinnedWorkspace(t *testing.T) {
	c := testConnection(t)
	a, b := newStateFixture(t, c), newStateFixture(t, c)
	asA := pinnedConn(t, c, a.ws)

	team, err := db.New(asA).CreateTeam(t.Context(), &db.CreateTeamParams{Name: "ops"})
	if err != nil || team.WorkspaceID != a.ws {
		t.Fatalf("CreateTeam = %+v, %v, want a team of the pinned workspace", team, err)
	}

	// Naming another workspace, or moving a row there, is refused.
	_, err = asA.Exec(t.Context(), `INSERT INTO teams (workspace_id, name) VALUES ($1, 'smuggled')`, b.ws)
	if pgCode(err) != pgerrcode.InsufficientPrivilege {
		t.Errorf("insert into another workspace: %v, want a row security violation", err)
	}
	_, err = asA.Exec(t.Context(), `UPDATE teams SET workspace_id = $1 WHERE id = $2`, b.ws, team.ID)
	if pgCode(err) != pgerrcode.InsufficientPrivilege {
		t.Errorf("move into another workspace: %v, want a row security violation", err)
	}

	// The composite keys keep a row from pointing across workspaces.
	_, err = asA.Exec(t.Context(), `INSERT INTO team_members (user_id, team_id) VALUES ($1, $2)`, b.u, team.ID)
	if pgCode(err) != pgerrcode.ForeignKeyViolation {
		t.Errorf("team member of another workspace: %v, want a foreign key violation", err)
	}

	// A workspace row is only created under its own pin.
	second := uuid.NewV7().String()
	_, err = asA.Exec(t.Context(), `INSERT INTO workspaces (id, slug, name) VALUES ($1, $2, 'second')`, second, second)
	if pgCode(err) != pgerrcode.InsufficientPrivilege {
		t.Errorf("second workspace from a pinned one: %v, want a row security violation", err)
	}

	// Without a pin the default is NULL. System code has to name the workspace.
	if _, err := c.Sys().CreateTeam(t.Context(), &db.CreateTeamParams{Name: "nowhere"}); pgCode(
		err,
	) != pgerrcode.NotNullViolation {
		t.Errorf("unpinned insert: %v, want a not null violation", err)
	}
	if _, err := db.New(c.Pool).CreateTeam(t.Context(), &db.CreateTeamParams{Name: "nowhere"}); err == nil {
		t.Error("the app role inserted a row without a pin")
	}
}

// Nothing leaves the request pool without a workspace on the context.
func TestUnpinnedRequestFailsClosed(t *testing.T) {
	c := testConnection(t)
	if err := c.TenantTx(
		t.Context(),
		func(*db.Queries) error { return nil },
	); !errors.Is(
		err,
		db.ErrWorkspaceNotPinned,
	) {
		t.Errorf("transaction: err = %v, want ErrWorkspaceNotPinned", err)
	}
	if _, err := c.Tenant().GetOwner(t.Context()); !errors.Is(err, db.ErrWorkspaceNotPinned) {
		t.Errorf("single statement: err = %v, want ErrWorkspaceNotPinned", err)
	}
	var n int
	if err := c.Pool.QueryRow(t.Context(), "SELECT 1").Scan(&n); !errors.Is(err, db.ErrWorkspaceNotPinned) {
		t.Errorf("raw query: err = %v, want ErrWorkspaceNotPinned", err)
	}
}

// The pin is set each time a connection leaves the pool. A pool of one forces every call onto the same connection.
func TestPinFollowsTheContext(t *testing.T) {
	t.Setenv("NOKKU_DB_MAX_CONNS", "1")
	c := testConnection(t)
	a, b := newStateFixture(t, c), newStateFixture(t, c)

	for round := range 3 {
		for _, f := range []stateFixture{a, b} {
			ws, err := c.Tenant().GetWorkspace(pinned(t, f.ws))
			if err != nil || ws.ID != f.ws {
				t.Fatalf("round %d: GetWorkspace = %v, %v, want %s", round, ws, err, f.ws)
			}
			owner, err := c.Tenant().GetOwner(pinned(t, f.ws))
			if err != nil || owner.ID != f.owner {
				t.Fatalf("round %d: GetOwner = %v, %v, want %s", round, owner, err, f.owner)
			}
		}
		// The connection still carries b's pin here. It must not be usable.
		if _, err := c.Tenant().GetOwner(t.Context()); !errors.Is(err, db.ErrWorkspaceNotPinned) {
			t.Fatalf("round %d: unpinned read after a pinned one: %v", round, err)
		}
	}
	// A transaction is pinned the same way.
	asOwner(t, c, a, func(q *db.Queries) error {
		owner, err := q.GetOwner(t.Context())
		if err == nil && owner.ID != a.owner {
			t.Errorf("transaction saw the owner of another workspace")
		}
		return err
	})
}

// Many requests of two workspaces share a small pool. Each only ever sees its own workspace.
func TestPinHoldsUnderConcurrency(t *testing.T) {
	t.Setenv("NOKKU_DB_MAX_CONNS", "3")
	c := testConnection(t)
	fixtures := []stateFixture{newStateFixture(t, c), newStateFixture(t, c)}

	var wg sync.WaitGroup
	for worker := range 16 {
		wg.Go(func() {
			f := fixtures[worker%2]
			ctx := pinned(t, f.ws)
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

// A system connection is never pinned, so an insert that names no workspace fails even right after pinned traffic.
func TestSystemConnectionsStayUnpinned(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	if _, err := c.Tenant().GetOwner(pinned(t, f.ws)); err != nil {
		t.Fatalf("pinned read: %v", err)
	}
	for range 8 {
		if _, err := c.Sys().CreateTeam(pinned(t, f.ws), &db.CreateTeamParams{Name: "nowhere"}); pgCode(
			err,
		) != pgerrcode.NotNullViolation {
			t.Fatalf("system insert without a workspace: %v, want a not null violation", err)
		}
	}
}

// One read of the pinned workspace, the way a handler does it today and the way it would with the pool hook.
func BenchmarkSingleRead(b *testing.B) {
	c := testConnection(b)
	id := uuid.NewV7().String()
	if _, err := c.sysPool.Exec(b.Context(), `INSERT INTO workspaces (id, slug, name) VALUES ($1, $2, 'bench')`,
		id, id); err != nil {
		b.Fatalf("seed: %v", err)
	}
	ctx := actor.WithWorkspace(b.Context(), actor.Workspace{ID: id})

	b.Run("transaction", func(b *testing.B) {
		for b.Loop() {
			if err := c.TenantTx(ctx, func(q *db.Queries) error {
				_, err := q.GetWorkspace(ctx)
				return err
			}); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("direct", func(b *testing.B) {
		for b.Loop() {
			if _, err := c.Tenant().GetWorkspace(ctx); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// The system role is the one way around row security, see Connection.SysTx.
func TestSystemRoleSeesEveryWorkspace(t *testing.T) {
	c := testConnection(t)
	a, b := newStateFixture(t, c), newStateFixture(t, c)
	if got := count(t, c.sysPool, "SELECT COUNT(*) FROM users WHERE workspace_id = ANY ($1)",
		[]string{a.ws, b.ws}); got != 4 {
		t.Fatalf("system role sees %d users of the two fixtures, want 4", got)
	}
}

// The app role holds no DELETE on the audit table. The trigger refuses the system role outside the retention job.
func TestAuditLogIsAppendOnly(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	if err := c.Sys().InsertAuditLog(t.Context(), &db.InsertAuditLogParams{
		WorkspaceID: f.ws, Action: "Test", Ok: true, Details: []byte("{}"),
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	const del = "DELETE FROM audit.audit_logs WHERE workspace_id = $1"
	if _, err := c.Pool.Exec(pinned(t, f.ws), del, f.ws); pgCode(err) != pgerrcode.InsufficientPrivilege {
		t.Errorf("app role delete: err = %v, want insufficient privilege", err)
	}
	if _, err := c.sysPool.Exec(t.Context(), del, f.ws); err == nil {
		t.Error("system role deleted an audit row without opting in")
	}
}

func TestAppRoleCannotWriteAudit(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)

	err := c.TenantTx(pinned(t, f.ws), func(q *db.Queries) error {
		return q.InsertAuditLog(t.Context(), &db.InsertAuditLogParams{
			WorkspaceID: f.ws,
			Action:      "forged",
			ActorKind:   "user",
			Details:     []byte("{}"),
		})
	})
	if err == nil {
		t.Fatal("app role wrote an audit row")
	}
}

func TestAuditLogScopes(t *testing.T) {
	c := testConnection(t)
	a, b := newStateFixture(t, c), newStateFixture(t, c)
	for _, row := range []struct{ ws, actor string }{{a.ws, a.u}, {b.ws, b.u}, {b.ws, b.owner}} {
		if err := c.Sys().InsertAuditLog(t.Context(), &db.InsertAuditLogParams{
			WorkspaceID: row.ws, ActorID: row.actor, Action: "Test", Ok: true, Details: []byte("{}"),
		}); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	list := func(ws string) int {
		t.Helper()
		var rows []*db.ListAuditLogsRow
		if err := c.TenantTx(pinned(t, ws), func(q *db.Queries) (err error) {
			rows, err = q.ListAuditLogs(t.Context(), &db.ListAuditLogsParams{Limit: 100})
			return err
		}); err != nil {
			t.Fatalf("list: %v", err)
		}
		return len(rows)
	}
	if n := list(a.ws); n != 1 {
		t.Errorf("workspace a has %d rows, want 1", n)
	}
	if n := list(b.ws); n != 2 {
		t.Errorf("workspace b has %d rows, want 2", n)
	}

	if _, err := c.sysPool.Exec(t.Context(), "DELETE FROM workspaces WHERE id = $1", a.ws); err != nil {
		t.Fatalf("delete workspace with audit rows: %v", err)
	}
}
