//go:build integration

package db_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
)

// stateFixture is one workspace where user u reaches account p on a daemon target directly and through team.
type stateFixture struct {
	ws, owner, u, team, daemon, target, account string
}

func newStateFixture(t *testing.T, c *conn) stateFixture {
	t.Helper()
	f := stateFixture{
		ws:      uuid.NewV7().String(),
		owner:   uuid.NewV7().String(),
		u:       uuid.NewV7().String(),
		team:    uuid.NewV7().String(),
		daemon:  uuid.NewV7().String(),
		target:  uuid.NewV7().String(),
		account: uuid.NewV7().String(),
	}
	// The simple protocol substitutes arguments client-side, which allows several statements in one Exec.
	_, err := c.sysPool.Exec(t.Context(), `
		INSERT INTO workspaces (id, slug, name) VALUES ($1, $1, 'ws');
		INSERT INTO users (id, workspace_id, email, role)
		VALUES ($2, $1, $2 || '@test', 5), ($3, $1, $3 || '@test', 2);
		INSERT INTO teams (id, workspace_id, name) VALUES ($4, $1, 'team');
		INSERT INTO team_members (workspace_id, user_id, team_id) VALUES ($1, $3, $4);
		INSERT INTO daemons (id, workspace_id, name, status) VALUES ($5, $1, 'd', 2);
		INSERT INTO targets (id, workspace_id, daemon_id, name) VALUES ($6, $1, $5, 't');
		INSERT INTO target_accounts (id, workspace_id, target_id, username) VALUES ($7, $1, $6, 'deploy');
		INSERT INTO grants (account_id, workspace_id, user_id) VALUES ($7, $1, $3);
		INSERT INTO grants (account_id, workspace_id, team_id) VALUES ($7, $1, $4);
	`, pgx.QueryExecModeSimpleProtocol, f.ws, f.owner, f.u, f.team, f.daemon, f.target, f.account)
	if err != nil {
		t.Fatalf("seed fixture: %v", err)
	}
	return f
}

// conn is a Connection plus a raw pool as nokku_system, for the SQL no query covers.
type conn struct {
	*db.Connection

	sysPool *pgxpool.Pool
}

func testConnection(t testing.TB) *conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	c, err := db.NewConnection(t.Context())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	// The system role logs in with the password of the app role and is never pinned.
	cfg := c.Pool.Config()
	cfg.ConnConfig.User = "nokku_system"
	cfg.PrepareConn = nil
	sysPool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatalf("connect as nokku_system: %v", err)
	}
	t.Cleanup(sysPool.Close)
	if err := sysPool.Ping(ctx); err != nil {
		t.Fatalf("ping as nokku_system: %v", err)
	}
	return &conn{Connection: c, sysPool: sysPool}
}

func stateVersion(t *testing.T, c *conn, ws string) int64 {
	t.Helper()
	v, err := c.Sys().GetWorkspaceStateVersion(t.Context(), ws)
	if err != nil {
		t.Fatalf("read state version: %v", err)
	}
	return v
}

func grantedIDs(t *testing.T, c *conn, target string) []string {
	t.Helper()
	rows, err := c.Sys().ListAccountSubjectsForTarget(t.Context(), target)
	if err != nil {
		t.Fatalf("list principals: %v", err)
	}
	if len(rows) == 0 {
		return nil
	}
	return rows[0].Ids
}

// asOwner runs fn the way API handlers do: nokku_app, pinned to the workspace.
func asOwner(t *testing.T, c *conn, f stateFixture, fn func(*db.Queries) error) {
	t.Helper()
	ctx := actor.ContextWithPrincipal(
		t.Context(),
		actor.Principal{ID: f.owner, Kind: actor.KindUser, Role: nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER},
	)
	ctx = actor.WithWorkspace(ctx, actor.Workspace{ID: f.ws})
	if err := c.TenantTx(ctx, fn); err != nil {
		t.Fatalf("workspace tx: %v", err)
	}
}

func listen(t *testing.T, c *conn) *pgx.Conn {
	t.Helper()
	conn, err := pgx.ConnectConfig(t.Context(), c.Pool.Config().ConnConfig)
	if err != nil {
		t.Fatalf("listen connect: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	if _, err := conn.Exec(t.Context(), "LISTEN nokku_state"); err != nil {
		t.Fatalf("listen: %v", err)
	}
	return conn
}

func waitNotify(t *testing.T, conn *pgx.Conn, ws string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			t.Fatalf("no state notification for %s: %v", ws, err)
		}
		if n.Payload == ws {
			return
		}
	}
}

func TestStateVersionBumpsOnAccessChanges(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	conn := listen(t, c)

	if got := grantedIDs(t, c, f.target); len(got) != 1 || got[0] != f.u {
		t.Fatalf("granted ids = %v, want [%s]", got, f.u)
	}

	before := stateVersion(t, c, f.ws)
	asOwner(t, c, f, func(q *db.Queries) error {
		return q.RemoveTeamMember(t.Context(), &db.RemoveTeamMemberParams{TeamID: f.team, UserID: f.u})
	})
	waitNotify(t, conn, f.ws)
	if after := stateVersion(t, c, f.ws); after <= before {
		t.Fatalf("team member removal: version %d -> %d, want a bump", before, after)
	}

	before = stateVersion(t, c, f.ws)
	asOwner(t, c, f, func(q *db.Queries) error {
		return q.DeleteUser(t.Context(), f.u)
	})
	waitNotify(t, conn, f.ws)
	if after := stateVersion(t, c, f.ws); after <= before {
		t.Fatalf("user removal: version %d -> %d, want a bump", before, after)
	}
	if got := grantedIDs(t, c, f.target); len(got) != 0 {
		t.Fatalf("removed user still granted: %v", got)
	}
}

// One transaction bumps once, however many rows it touches. A team with thousands of grants is one statement.
func TestStateVersionBumpsOncePerTransaction(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)

	before := stateVersion(t, c, f.ws)
	asOwner(t, c, f, func(q *db.Queries) error {
		if err := q.RemoveTeamMember(t.Context(), &db.RemoveTeamMemberParams{TeamID: f.team, UserID: f.u}); err != nil {
			return err
		}
		// Both grants of the fixture go with it.
		return q.DeleteTargetAccount(t.Context(), f.account)
	})
	if after := stateVersion(t, c, f.ws); after != before+1 {
		t.Fatalf("three removals in one transaction: version %d -> %d, want one bump", before, after)
	}

	asOwner(t, c, f, func(q *db.Queries) error {
		return q.SetUserActive(t.Context(), &db.SetUserActiveParams{ID: f.u, Active: false})
	})
	if after := stateVersion(t, c, f.ws); after != before+2 {
		t.Fatalf("the next transaction: version %d, want %d", after, before+2)
	}
}

// A deactivated account must leave every daemon's map at once, or a cert it holds works until it expires.
func TestDeactivatedUserLosesAccess(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	conn := listen(t, c)

	setActive := func(active bool) {
		if err := c.Sys().
			SetUserActive(t.Context(), &db.SetUserActiveParams{ID: f.u, Active: active}); err != nil {
			t.Fatalf("set active=%v: %v", active, err)
		}
	}

	before := stateVersion(t, c, f.ws)
	setActive(false)
	waitNotify(t, conn, f.ws)
	if after := stateVersion(t, c, f.ws); after <= before {
		t.Fatalf("deactivation: version %d -> %d, want a bump", before, after)
	}
	if got := grantedIDs(t, c, f.target); len(got) != 0 {
		t.Fatalf("deactivated user still granted: %v", got)
	}

	setActive(true)
	waitNotify(t, conn, f.ws)
	if got := grantedIDs(t, c, f.target); len(got) != 1 || got[0] != f.u {
		t.Fatalf("reactivated user: granted ids = %v, want [%s]", got, f.u)
	}
}

func TestStateVersionIgnoresHeartbeatWrites(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)

	before := stateVersion(t, c, f.ws)
	asOwner(t, c, f, func(q *db.Queries) error {
		if err := q.UpdateDaemonMetadata(t.Context(), &db.UpdateDaemonMetadataParams{
			DaemonID: f.daemon,
			Metadata: []byte(`{"host":"x"}`),
		}); err != nil {
			return err
		}
		if _, err := q.UpdateTarget(t.Context(), &db.UpdateTargetParams{
			TargetID:  f.target,
			Metadata:  []byte(`{"os":"linux"}`),
			Endpoints: []string{"10.0.0.1:4022"},
		}); err != nil {
			return err
		}
		return q.InsertTargetAccounts(t.Context(), &db.InsertTargetAccountsParams{
			TargetID:  f.target,
			Usernames: []string{"deploy", "backup"},
		})
	})
	if after := stateVersion(t, c, f.ws); after != before {
		t.Fatalf("heartbeat writes moved the version %d -> %d", before, after)
	}
}

func TestGrantRejectsForeignTeam(t *testing.T) {
	c := testConnection(t)
	a := newStateFixture(t, c)
	b := newStateFixture(t, c)

	_, err := c.sysPool.Exec(t.Context(),
		`INSERT INTO grants (account_id, workspace_id, team_id) VALUES ($1, $2, $3)`,
		a.account, a.ws, b.team)
	if err == nil {
		t.Fatal("granted a team from another workspace")
	}
}

// The code reads the target of a daemon as one row.
func TestDaemonServesOneTarget(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)

	_, err := c.sysPool.Exec(t.Context(),
		`INSERT INTO targets (workspace_id, daemon_id, name) VALUES ($1, $2, 'second')`, f.ws, f.daemon)
	if err == nil {
		t.Fatal("a daemon got a second target")
	}
}

func TestRecordingRejectsForeignDaemon(t *testing.T) {
	c := testConnection(t)
	a := newStateFixture(t, c)
	b := newStateFixture(t, c)

	_, err := c.sysPool.Exec(t.Context(), `
		INSERT INTO recordings (workspace_id, daemon_id, daemon_name, username, key) VALUES ($1, $2, 'd', 'root', 'k')`,
		a.ws, b.daemon)
	if err == nil {
		t.Fatal("filed a recording under a daemon of another workspace")
	}
}

// Who it was stays with the recording. The account may be gone by the time someone looks.
func TestRecordingKeepsTheSubjectsName(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	id := uuid.NewV7().String()
	asOwner(t, c, f, func(q *db.Queries) error {
		_, err := q.CreateRecording(t.Context(), &db.CreateRecordingParams{
			ID: id, DaemonID: f.daemon, Username: "deploy", SubjectID: &f.u, Key: crypto.EncryptedBytes("k"),
		})
		if err != nil {
			return err
		}
		return q.DeleteUser(t.Context(), f.u)
	})

	var name string
	err := c.sysPool.QueryRow(t.Context(), `SELECT subject_name FROM recordings WHERE id = $1`, id).Scan(&name)
	if err != nil {
		t.Fatalf("read the recording: %v", err)
	}
	if want := f.u + "@test"; name != want {
		t.Fatalf("subject name = %q, want %q", name, want)
	}
}

// Three checks tie the subject column to the kind. They also have to keep a token to one subject, and scim to none.
func TestAccessTokenTakesTheSubjectOfItsKind(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	var sa string
	err := c.sysPool.QueryRow(t.Context(),
		`INSERT INTO service_accounts (workspace_id, name) VALUES ($1, 'ci') RETURNING id`, f.ws).Scan(&sa)
	if err != nil {
		t.Fatalf("service account: %v", err)
	}
	insert := func(kind string, user, serviceAccount, daemon *string) error {
		_, err := c.sysPool.Exec(t.Context(), `
			INSERT INTO access_tokens (token_hash, workspace_id, kind, method, user_id, service_account_id, daemon_id)
			VALUES (uuidv7()::TEXT, $1, $2, 'test', $3, $4, $5)`,
			f.ws, kind, user, serviceAccount, daemon)
		return err
	}

	for name, tok := range map[string]struct {
		kind                         string
		user, serviceAccount, daemon *string
	}{
		"a user and a service account":   {"user", &f.u, &sa, nil},
		"a daemon and a service account": {"daemon", nil, &sa, &f.daemon},
		"a cli token of nobody":          {"cli", nil, nil, nil},
		"a scim token of a user":         {"scim", &f.u, nil, nil},
		"a scim token of a daemon":       {"scim", nil, nil, &f.daemon},
		"a user token of a daemon":       {"user", nil, nil, &f.daemon},
	} {
		if err := insert(tok.kind, tok.user, tok.serviceAccount, tok.daemon); err == nil {
			t.Errorf("stored %s", name)
		}
	}
	for name, tok := range map[string]struct {
		kind                         string
		user, serviceAccount, daemon *string
	}{
		"user":            {"user", &f.u, nil, nil},
		"cli":             {"cli", &f.u, nil, nil},
		"service account": {"service_account", nil, &sa, nil},
		"daemon":          {"daemon", nil, nil, &f.daemon},
		"scim":            {"scim", nil, nil, nil},
	} {
		if err := insert(tok.kind, tok.user, tok.serviceAccount, tok.daemon); err != nil {
			t.Errorf("a %s token: %v", name, err)
		}
	}
}

// The session of a deleted daemon stays for the REJECTED answer. A host that is gone never asks, so it expires.
func TestDeletedDaemonsTokenExpires(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	_, err := c.sysPool.Exec(t.Context(), `
		INSERT INTO access_tokens (token_hash, workspace_id, kind, method, daemon_id)
		VALUES ($1::TEXT, $2, 'daemon', 'device', $1::UUID)`, f.daemon, f.ws)
	if err != nil {
		t.Fatalf("daemon session: %v", err)
	}
	// A certificate lives a year at most, so the host is told for as long as one could still open it.
	expires := func() (never, afterAYear bool) {
		t.Helper()
		err := c.sysPool.QueryRow(t.Context(), `
			SELECT expires_at IS NULL, COALESCE(expires_at > NOW() + INTERVAL '365 days', FALSE)
			FROM access_tokens WHERE token_hash = $1`, f.daemon).Scan(&never, &afterAYear)
		if err != nil {
			t.Fatalf("read the session: %v", err)
		}
		return never, afterAYear
	}
	if never, _ := expires(); !never {
		t.Fatal("the session of a live daemon expires")
	}

	asOwner(t, c, f, func(q *db.Queries) error {
		_, err := q.DeleteDaemon(t.Context(), f.daemon)
		return err
	})
	if never, afterAYear := expires(); never || !afterAYear {
		t.Fatalf("the session of a deleted daemon: never expires %v, outlives a certificate %v", never, afterAYear)
	}
}

// An unspecified status locks a daemon out of its control stream, so the schema refuses it.
func TestDaemonStatusRejectsUnspecified(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)

	_, err := c.sysPool.Exec(t.Context(), `UPDATE daemons SET status = 0 WHERE id = $1`, f.daemon)
	if err == nil {
		t.Fatal("stored a daemon with status 0")
	}
}

// Parallel redemptions of a one-use token spend it exactly once.
func TestRedeemTokenOnce(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	id := uuid.NewV7().String()
	hash := crypto.HashedToken("h-" + id)
	asOwner(t, c, f, func(q *db.Queries) error {
		_, err := q.CreateJoinToken(t.Context(), &db.CreateJoinTokenParams{
			ID:        id,
			Kind:      nokkuv1.JoinTokenKind_JOIN_TOKEN_KIND_INVITE,
			TokenHash: hash,
			MaxUses:   new(int32(1)),
			Role:      new(nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER),
		})
		return err
	})

	const n = 8
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			_, err := c.Sys().RedeemJoinToken(t.Context(), &db.RedeemJoinTokenParams{
				ID: id, Kind: nokkuv1.JoinTokenKind_JOIN_TOKEN_KIND_INVITE, TokenHash: hash,
			})
			if err == nil {
				wins.Add(1)
			} else if !errors.Is(err, pgx.ErrNoRows) {
				t.Errorf("redeem: %v", err)
			}
		})
	}
	wg.Wait()
	if got := wins.Load(); got != 1 {
		t.Fatalf("%d redemptions succeeded, want 1", got)
	}
}

// Unchanged reports must not rewrite the rows, or every grant change costs a write per daemon.
func TestSyncReportSkipsUnchangedRows(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	rowVersions := func() (daemon, target string) {
		t.Helper()
		err := c.sysPool.QueryRow(t.Context(), `
			SELECT d.xmin::TEXT, t.xmin::TEXT FROM daemons d JOIN targets t ON t.daemon_id = d.id WHERE d.id = $1
		`, f.daemon).Scan(&daemon, &target)
		if err != nil {
			t.Fatalf("read row versions: %v", err)
		}
		return daemon, target
	}
	report := func(endpoints []string) {
		t.Helper()
		if err := c.Sys().UpdateDaemonMetadata(t.Context(), &db.UpdateDaemonMetadataParams{
			DaemonID: f.daemon, Metadata: []byte(`{"host": "a"}`),
		}); err != nil {
			t.Fatalf("report daemon metadata: %v", err)
		}
		if err := c.Sys().UpdateTargetReport(t.Context(), &db.UpdateTargetReportParams{
			TargetID: f.target, Metadata: []byte(`{"os": "linux"}`), Endpoints: endpoints,
		}); err != nil {
			t.Fatalf("report target: %v", err)
		}
	}

	report([]string{"10.0.0.5:4022"})
	daemon, target := rowVersions()

	report([]string{"10.0.0.5:4022"})
	report(nil)
	if d, tg := rowVersions(); d != daemon || tg != target {
		t.Errorf("an unchanged report rewrote a row: daemon %s to %s, target %s to %s", daemon, d, target, tg)
	}

	report([]string{"10.0.0.6:4022"})
	if _, tg := rowVersions(); tg == target {
		t.Error("a changed endpoint was not written")
	}
}

func TestInsertTargetPrincipalsStopsAtTheCap(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	insert := func(limit int32, names ...string) {
		t.Helper()
		if err := c.Sys().InsertTargetAccounts(t.Context(), &db.InsertTargetAccountsParams{
			TargetID: f.target, Usernames: names, MaxAccounts: limit,
		}); err != nil {
			t.Fatalf("insert principals: %v", err)
		}
	}
	count := func() (n int) {
		t.Helper()
		if err := c.sysPool.QueryRow(t.Context(),
			`SELECT COUNT(*) FROM target_accounts WHERE target_id = $1`, f.target).Scan(&n); err != nil {
			t.Fatalf("count principals: %v", err)
		}
		return n
	}

	// The fixture holds one principal already.
	insert(3, "a", "b")
	if got := count(); got != 3 {
		t.Fatalf("below the cap: %d principals, want 3", got)
	}
	insert(3, "c")
	if got := count(); got != 3 {
		t.Errorf("at the cap: %d principals, want 3", got)
	}
}
