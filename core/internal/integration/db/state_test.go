//go:build integration

package db_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"uuid"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/crypto"
	"github.com/nokku-sh/nokku/core/internal/db"
)

// stateFixture is a workspace where u reaches account directly and via team.
type stateFixture struct {
	ws, owner, u, team, daemon, target, account, ca string
}

// conn is a Connection plus a nokku_system pool, for the SQL no query covers.
type conn struct {
	*db.Connection

	sysPool *pgxpool.Pool
}

// watcher counts the notifications that tell the core a workspace's access changed.
type watcher struct {
	conn *pgx.Conn
	ws   string
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
		ca:      uuid.NewV7().String(),
	}
	// The simple protocol allows several statements in one Exec.
	_, err := c.sysPool.Exec(t.Context(), `
		INSERT INTO workspaces (id, slug, name) VALUES ($1, $1, 'ws');
		INSERT INTO users (id, workspace_id, email, role)
		VALUES ($2, $1, $2 || '@test', 5), ($3, $1, $3 || '@test', 2);
		INSERT INTO teams (id, workspace_id, name) VALUES ($4, $1, 'team');
		INSERT INTO team_members (workspace_id, user_id, team_id) VALUES ($1, $3, $4);
		INSERT INTO ssh_cas (id, workspace_id, user_public_key, host_public_key, user_ttl)
		VALUES ($8, $1, 'pub', 'host-pub', '1 hour');
		INSERT INTO daemons (id, workspace_id, status) VALUES ($5, $1, 2);
		INSERT INTO targets (id, workspace_id, daemon_id, name) VALUES ($6, $1, $5, 't');
		INSERT INTO target_accounts (id, workspace_id, target_id, username) VALUES ($7, $1, $6, 'deploy');
		INSERT INTO grants (account_id, workspace_id, user_id) VALUES ($7, $1, $3);
		INSERT INTO grants (account_id, workspace_id, team_id) VALUES ($7, $1, $4);
	`, pgx.QueryExecModeSimpleProtocol, f.ws, f.owner, f.u, f.team, f.daemon, f.target, f.account, f.ca)
	require.NoError(t, err, "seed fixture")
	return f
}

func testConnection(t testing.TB) *conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	c, err := db.NewConnection(t.Context())
	require.NoError(t, err, "connect")
	// The system role logs in with the app role's password and is never pinned.
	cfg := c.Pool.Config()
	cfg.ConnConfig.User = "nokku_system"
	cfg.PrepareConn = nil
	sysPool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	require.NoError(t, err, "connect as nokku_system")
	t.Cleanup(sysPool.Close)
	require.NoError(t, sysPool.Ping(ctx), "ping as nokku_system")
	return &conn{Connection: c, sysPool: sysPool}
}

// watch has to start before the change it counts.
func watch(t *testing.T, c *conn, ws string) *watcher {
	t.Helper()
	return &watcher{conn: listen(t, c), ws: ws}
}

// seen is how many came since the last call. One on its way gets a moment to arrive.
func (w *watcher) seen(t *testing.T) int {
	t.Helper()
	n := 0
	for {
		ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
		note, err := w.conn.WaitForNotification(ctx)
		cancel()
		if err != nil {
			require.ErrorIs(t, err, context.DeadlineExceeded)
			return n
		}
		if note.Payload == w.ws {
			n++
		}
	}
}

func grantedIDs(t *testing.T, c *conn, target string) []string {
	t.Helper()
	rows, err := c.Sys().ListAccountSubjectsForTarget(t.Context(), target)
	require.NoError(t, err, "list granted subjects")
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
	require.NoError(t, c.TenantTx(ctx, fn), "workspace tx")
}

func listen(t *testing.T, c *conn) *pgx.Conn {
	t.Helper()
	conn, err := pgx.ConnectConfig(t.Context(), c.Pool.Config().ConnConfig)
	require.NoError(t, err, "listen connect")
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	_, err = conn.Exec(t.Context(), "LISTEN nokku_state")
	require.NoError(t, err, "listen")
	return conn
}

func TestAccessChangesNotify(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	w := watch(t, c, f.ws)

	require.Equal(t, []string{f.u}, grantedIDs(t, c, f.target))

	asOwner(t, c, f, func(q *db.Queries) error {
		return q.RemoveTeamMember(t.Context(), &db.RemoveTeamMemberParams{TeamID: f.team, UserID: f.u})
	})
	require.Equal(t, 1, w.seen(t), "a team member removal")

	asOwner(t, c, f, func(q *db.Queries) error {
		return q.DeleteUser(t.Context(), f.u)
	})
	require.Equal(t, 1, w.seen(t), "a user removal")
	require.Empty(t, grantedIDs(t, c, f.target), "removed user still granted")
}

// targets has no trigger, a deleted server reaches daemons via its accounts.
func TestDeletingATargetNotifies(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	w := watch(t, c, f.ws)
	asOwner(t, c, f, func(q *db.Queries) error {
		_, err := q.DeleteTarget(t.Context(), f.target)
		return err
	})
	require.Equal(t, 1, w.seen(t), "a target removal")
}

// One transaction notifies once, however many rows it touches. A team with
// thousands of grants is one statement.
func TestAccessChangesNotifyOncePerTransaction(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	w := watch(t, c, f.ws)

	asOwner(t, c, f, func(q *db.Queries) error {
		if err := q.RemoveTeamMember(t.Context(), &db.RemoveTeamMemberParams{TeamID: f.team, UserID: f.u}); err != nil {
			return err
		}
		// Both grants of the fixture go with it.
		return q.DeleteTargetAccount(t.Context(), f.account)
	})
	require.Equal(t, 1, w.seen(t), "three removals in one transaction")

	asOwner(t, c, f, func(q *db.Queries) error {
		return q.SetUserActive(t.Context(), &db.SetUserActiveParams{ID: f.u, Active: false})
	})
	require.Equal(t, 1, w.seen(t), "the next transaction")
}

// A deactivated account leaves every daemon's map at once, or a cert it holds
// works until it expires.
func TestDeactivatedUserLosesAccess(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	w := watch(t, c, f.ws)

	setActive := func(active bool) {
		require.NoError(t, c.Sys().SetUserActive(t.Context(), &db.SetUserActiveParams{ID: f.u, Active: active}),
			"set active=%v", active)
	}

	setActive(false)
	require.Equal(t, 1, w.seen(t), "a deactivation")
	require.Empty(t, grantedIDs(t, c, f.target), "deactivated user still granted")

	setActive(true)
	require.Equal(t, 1, w.seen(t), "a reactivation")
	require.Equal(t, []string{f.u}, grantedIDs(t, c, f.target), "reactivated user")
}

// What a daemon reports about its host changes nobody's access.
func TestAServersReportNotifiesNobody(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	w := watch(t, c, f.ws)

	asOwner(t, c, f, func(q *db.Queries) error {
		if err := q.UpdateDaemonVersion(t.Context(), &db.UpdateDaemonVersionParams{
			DaemonID: f.daemon,
			Version:  "1.0.0",
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
	require.Zero(t, w.seen(t), "a server's report looked like an access change")
}

func TestGrantRejectsForeignTeam(t *testing.T) {
	c := testConnection(t)
	a := newStateFixture(t, c)
	b := newStateFixture(t, c)

	_, err := c.sysPool.Exec(t.Context(),
		`INSERT INTO grants (account_id, workspace_id, team_id) VALUES ($1, $2, $3)`,
		a.account, a.ws, b.team)
	assert.Equal(t, pgerrcode.ForeignKeyViolation, pgCode(err), "granted a team from another workspace: %v", err)
}

// A server has no tie to SSH keys, so a CA can go while targets stay.
func TestTargetNeedsNoCA(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	_, err := c.sysPool.Exec(t.Context(), `DELETE FROM ssh_cas WHERE id = $1`, f.ca)
	require.NoError(t, err, "a target held on to the CA")
	asOwner(t, c, f, func(q *db.Queries) error {
		_, err := q.CreateTarget(t.Context(), &db.CreateTargetParams{Name: "no-ca"})
		return err
	})
}

// The code reads the target of a daemon as one row.
func TestDaemonServesOneTarget(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)

	_, err := c.sysPool.Exec(t.Context(),
		`INSERT INTO targets (workspace_id, daemon_id, name) VALUES ($1, $2, 'second')`, f.ws, f.daemon)
	assert.Equal(t, pgerrcode.UniqueViolation, pgCode(err), "a daemon got a second target: %v", err)
}

func TestRecordingRejectsForeignDaemon(t *testing.T) {
	c := testConnection(t)
	a := newStateFixture(t, c)
	b := newStateFixture(t, c)

	_, err := c.sysPool.Exec(t.Context(), `
		INSERT INTO recordings (workspace_id, daemon_id, daemon_name, username, key) VALUES ($1, $2, 'd', 'root', 'k')`,
		a.ws, b.daemon)
	assert.Equal(
		t,
		pgerrcode.ForeignKeyViolation,
		pgCode(err),
		"filed a recording under a daemon of another workspace: %v",
		err,
	)
}

// Who it was stays with the recording. The account may be gone by then.
func TestRecordingKeepsTheSubjectsName(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	id := uuid.NewV7().String()
	asOwner(t, c, f, func(q *db.Queries) error {
		_, err := q.CreateRecording(t.Context(), &db.CreateRecordingParams{
			ID: id, DaemonID: f.daemon, Username: "deploy", SubjectID: &f.u, Key: []byte("k"),
		})
		if err != nil {
			return err
		}
		return q.DeleteUser(t.Context(), f.u)
	})

	var name string
	err := c.sysPool.QueryRow(t.Context(), `SELECT subject_name FROM recordings WHERE id = $1`, id).Scan(&name)
	require.NoError(t, err, "read the recording")
	require.Equal(t, f.u+"@test", name)
}

// Three checks tie the subject column to the kind. They also have to keep a
// token to one subject, and scim to none.
func TestAccessTokenTakesTheSubjectOfItsKind(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	var sa string
	err := c.sysPool.QueryRow(t.Context(),
		`INSERT INTO service_accounts (workspace_id, name) VALUES ($1, 'ci') RETURNING id`, f.ws).Scan(&sa)
	require.NoError(t, err, "service account")
	insert := func(kind string, user, serviceAccount, daemon *string) error {
		_, err := c.sysPool.Exec(t.Context(), `
			INSERT INTO access_tokens (
				token_hash, workspace_id, kind, method, user_id, service_account_id, daemon_id, expires_at, ssh_key
			)
			VALUES (uuidv7()::TEXT, $1, $2, 'test', $3, $4, $5, NOW() + INTERVAL '1 hour',
				CASE WHEN $2 = 'cli' THEN 'ssh-ed25519 AAAA' ELSE '' END)`,
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
		assert.Equal(t, pgerrcode.CheckViolation, pgCode(insert(tok.kind, tok.user, tok.serviceAccount, tok.daemon)),
			"stored %s", name)
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
		assert.NoError(t, insert(tok.kind, tok.user, tok.serviceAccount, tok.daemon), "a %s token", name)
	}
}

// The SSH key an nk session gets certificates for, no other kind has one.
func TestOnlyAnNKSessionCarriesAnSSHKey(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	insert := func(kind, sshKey string) error {
		_, err := c.sysPool.Exec(t.Context(), `
			INSERT INTO access_tokens (token_hash, workspace_id, kind, method, user_id, ssh_key)
			VALUES (uuidv7()::TEXT, $1, $2, 'test', $3, $4)`,
			f.ws, kind, f.u, sshKey)
		return err
	}

	assert.Equal(t, pgerrcode.CheckViolation, pgCode(insert("cli", "")), "an nk session without its key")
	assert.Equal(
		t,
		pgerrcode.CheckViolation,
		pgCode(insert("user", "ssh-ed25519 AAAA")),
		"a browser session with a key",
	)
}

// A service account token always ends, only a bound one can spend a job token.
func TestServiceAccountTokenHasAnEndDate(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	var sa string
	err := c.sysPool.QueryRow(t.Context(),
		`INSERT INTO service_accounts (workspace_id, name) VALUES ($1, 'ci') RETURNING id`, f.ws).Scan(&sa)
	require.NoError(t, err, "service account")
	insert := func(expiresAt *time.Time, binding string, jti *string) error {
		_, err := c.sysPool.Exec(t.Context(), `
			INSERT INTO access_tokens (
				token_hash, workspace_id, kind, method, service_account_id, expires_at, binding, workload_jti
			)
			VALUES (uuidv7()::TEXT, $1, 'service_account', 'test', $2, $3, $4, $5)`,
			f.ws, sa, expiresAt, binding, jti)
		return err
	}
	hour := new(time.Now().Add(time.Hour))
	assert.NoError(t, insert(hour, "", nil), "a dated key")
	assert.NoError(t, insert(hour, "jkt", new("https://ci.test job")), "the session of a job")
	err = insert(nil, "", nil)
	assert.Equal(t, pgerrcode.CheckViolation, pgCode(err), "a key with no end date: %v", err)
	err = insert(hour, "", new("https://ci.test other"))
	assert.Equal(t, pgerrcode.CheckViolation, pgCode(err), "the session of a job with no key behind it: %v", err)
	err = insert(hour, "jkt", new("https://ci.test job"))
	assert.Equal(t, pgerrcode.UniqueViolation, pgCode(err), "a job token stored twice: %v", err)
}

// The session of a deleted daemon stays for the REJECTED answer. A host that is
// gone never asks, so it expires.
func TestDeletedDaemonsTokenExpires(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	_, err := c.sysPool.Exec(t.Context(), `
		INSERT INTO access_tokens (token_hash, workspace_id, kind, method, daemon_id)
		VALUES ($1::TEXT, $2, 'daemon', 'device', $1::UUID)`, f.daemon, f.ws)
	require.NoError(t, err, "daemon session")
	// A certificate lives a year at most, the host is told for that long.
	expires := func() (never, afterAYear bool) {
		t.Helper()
		err := c.sysPool.QueryRow(t.Context(), `
			SELECT expires_at IS NULL, COALESCE(expires_at > NOW() + INTERVAL '365 days', FALSE)
			FROM access_tokens WHERE token_hash = $1`, f.daemon).Scan(&never, &afterAYear)
		require.NoError(t, err, "read the session")
		return never, afterAYear
	}
	never, _ := expires()
	require.True(t, never, "the session of a live daemon expires")

	asOwner(t, c, f, func(q *db.Queries) error {
		_, err := q.DeleteDaemon(t.Context(), f.daemon)
		return err
	})
	never, afterAYear := expires()
	require.False(t, never, "the session of a deleted daemon never expires")
	require.True(t, afterAYear, "the session of a deleted daemon ends before a certificate")
}

// An unspecified status locks a daemon out, so the schema refuses it.
func TestDaemonStatusRejectsUnspecified(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)

	_, err := c.sysPool.Exec(t.Context(), `UPDATE daemons SET status = 0 WHERE id = $1`, f.daemon)
	assert.Equal(t, pgerrcode.CheckViolation, pgCode(err), "stored a daemon with status 0: %v", err)
}

// Parallel redemptions of a one-use token spend it exactly once.
func TestRedeemTokenOnce(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	id := uuid.NewV7().String()
	hash := crypto.HashedToken("h-" + id)
	asOwner(t, c, f, func(q *db.Queries) error {
		_, err := q.CreateJoinToken(t.Context(), &db.CreateJoinTokenParams{
			TokenHash: hash,
			MaxUses:   new(int32(1)),
		})
		return err
	})

	const n = 8
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			_, err := c.Sys().RedeemJoinToken(t.Context(), hash)
			if err != nil {
				assert.ErrorIs(t, err, pgx.ErrNoRows, "redeem")
				return
			}
			wins.Add(1)
		})
	}
	wg.Wait()
	require.EqualValues(t, 1, wins.Load(), "redemptions that succeeded")
}

// An unchanged report rewrites no row, or every grant change costs a write.
func TestSyncReportSkipsUnchangedRows(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	rowVersions := func() (daemon, target string) {
		t.Helper()
		err := c.sysPool.QueryRow(t.Context(), `
			SELECT d.xmin::TEXT, t.xmin::TEXT FROM daemons d JOIN targets t ON t.daemon_id = d.id WHERE d.id = $1
		`, f.daemon).Scan(&daemon, &target)
		require.NoError(t, err, "read row versions")
		return daemon, target
	}
	report := func(endpoints []string) {
		t.Helper()
		require.NoError(t, c.Sys().UpdateDaemonVersion(t.Context(), &db.UpdateDaemonVersionParams{
			DaemonID: f.daemon, Version: "1.0.0",
		}), "report daemon version")
		require.NoError(t, c.Sys().UpdateTargetReport(t.Context(), &db.UpdateTargetReportParams{
			TargetID: f.target, Metadata: []byte(`{"os": "linux"}`), Endpoints: endpoints,
		}), "report target")
	}

	report([]string{"10.0.0.5:4022"})
	daemon, target := rowVersions()

	report([]string{"10.0.0.5:4022"})
	report(nil)
	d, tg := rowVersions()
	assert.Equal(t, daemon, d, "an unchanged report rewrote the daemon")
	assert.Equal(t, target, tg, "an unchanged report rewrote the target")

	report([]string{"10.0.0.6:4022"})
	_, tg = rowVersions()
	assert.NotEqual(t, target, tg, "a changed endpoint was not written")
}

func TestInsertTargetPrincipalsStopsAtTheCap(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	insert := func(limit int32, names ...string) {
		t.Helper()
		require.NoError(t, c.Sys().InsertTargetAccounts(t.Context(), &db.InsertTargetAccountsParams{
			TargetID: f.target, Usernames: names, MaxAccounts: limit,
		}), "insert accounts")
	}
	count := func() (n int) {
		t.Helper()
		require.NoError(t, c.sysPool.QueryRow(t.Context(),
			`SELECT COUNT(*) FROM target_accounts WHERE target_id = $1`, f.target).Scan(&n), "count accounts")
		return n
	}

	// The fixture holds one account already.
	insert(3, "a", "b")
	require.Equal(t, 3, count(), "below the cap")
	insert(3, "c")
	assert.Equal(t, 3, count(), "at the cap")
}
