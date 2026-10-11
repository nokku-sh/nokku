//go:build integration

package db_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// listenChanges listens the way internal/live does, on a connection of its own.
func listenChanges(t *testing.T, c *conn) *pgx.Conn {
	t.Helper()
	conn, err := pgx.ConnectConfig(t.Context(), c.Pool.Config().ConnConfig)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.WithoutCancel(t.Context())) })
	if _, err := conn.Exec(t.Context(), "LISTEN nokku_change"); err != nil {
		t.Fatalf("listen: %v", err)
	}
	return conn
}

// heard returns the tables announced for ws since the last call, sorted.
func heard(t *testing.T, conn *pgx.Conn, ws string) []string {
	t.Helper()
	var tables []string
	for {
		ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
		n, err := conn.WaitForNotification(ctx)
		cancel()
		if err != nil {
			slices.Sort(tables)
			return tables
		}
		if table, ok := strings.CutPrefix(n.Payload, ws+":"); ok {
			tables = append(tables, table)
		}
	}
}

// silentTables are the sign-ins. They change all day and no list shows them to others, so no console hears of them.
var silentTables = []string{"credentials", "known_devices", "one_time_tokens"}

// A new tenant table has to say whether a console hears its changes.
func TestEveryTenantTableAnnouncesOrIsSilent(t *testing.T) {
	c := testConnection(t)
	for _, table := range tenantTables(t, c) {
		got := count(t, c.sysPool, `
			SELECT COUNT(*) FROM pg_trigger
			WHERE tgrelid = ('public.' || $1)::regclass AND tgname LIKE 'notify_change%'`,
			table)
		want := int64(2)
		if slices.Contains(silentTables, table) {
			want = 0
		}
		if got != want {
			t.Errorf("%s: %d change triggers, want %d. Add it to the list in 001_base.sql or to silentTables",
				table, got, want)
		}
	}
}

// The update trigger names its columns, so a stamp costs nothing. A column it misses would change unheard.
func TestUpdateTriggerNamesEveryColumn(t *testing.T) {
	c := testConnection(t)
	for _, table := range tenantTables(t, c) {
		if slices.Contains(silentTables, table) {
			continue
		}
		var missing string
		err := c.sysPool.QueryRow(t.Context(), `
			SELECT COALESCE(string_agg(a.attname, ', '), '')
			FROM pg_attribute a
			JOIN pg_trigger tg ON tg.tgrelid = a.attrelid AND tg.tgname = 'notify_change_update'
			WHERE a.attrelid = ('public.' || $1)::regclass
				AND a.attnum > 0 AND NOT a.attisdropped AND a.attgenerated = ''
				AND a.attname NOT IN ('last_seen_at', 'last_used_at')
				AND a.attnum <> ALL (tg.tgattr::int2[])`,
			table).Scan(&missing)
		if err != nil {
			t.Fatalf("%s: %v", table, err)
		}
		if missing != "" {
			t.Errorf("%s: notify_change_update does not name %s, recreate the trigger", table, missing)
		}
	}
}

func TestChangesAreAnnounced(t *testing.T) {
	c := testConnection(t)
	conn := listenChanges(t, c)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := c.sysPool.Exec(t.Context(), sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}

	// One transaction that writes some tables twice, each is announced once.
	f := newStateFixture(t, c)
	want := []string{
		"daemons", "grants", "target_accounts", "targets", "team_members", "teams", "users", "workspaces",
	}
	if got := heard(t, conn, f.ws); !slices.Equal(got, want) {
		t.Fatalf("seeding announced %v, want %v", got, want)
	}

	exec(`UPDATE targets SET name = 'renamed' WHERE id = $1`, f.target)
	if got := heard(t, conn, f.ws); !slices.Equal(got, []string{"targets"}) {
		t.Errorf("a rename announced %v, want targets", got)
	}

	exec(`DELETE FROM grants WHERE account_id = $1`, f.account)
	if got := heard(t, conn, f.ws); !slices.Equal(got, []string{"grants"}) {
		t.Errorf("a delete announced %v, want grants", got)
	}

	exec(`UPDATE targets SET name = name WHERE id = $1`, f.target)
	exec(`UPDATE targets SET metadata = metadata || '{"last_manual_sync": "now"}' WHERE id = $1`, f.target)
	if got := heard(t, conn, f.ws); len(got) != 0 {
		t.Errorf("updates that change nothing a console shows announced %v", got)
	}

	// A sign-in is nobody's business, a key made or revoked is.
	exec(`INSERT INTO access_tokens (token_hash, workspace_id, user_id, kind, method)
		VALUES ('h-user', $1, $2, 'user', 'passkey')`, f.ws, f.u)
	if got := heard(t, conn, f.ws); len(got) != 0 {
		t.Errorf("a sign-in announced %v", got)
	}
	var sa string
	err := c.sysPool.QueryRow(t.Context(),
		`INSERT INTO service_accounts (workspace_id, name) VALUES ($1, 'ci') RETURNING id`, f.ws).Scan(&sa)
	if err != nil {
		t.Fatalf("service account: %v", err)
	}
	exec(`INSERT INTO access_tokens (token_hash, workspace_id, service_account_id, kind, method)
		VALUES ('h-key', $1, $2, 'service_account', 'token')`, f.ws, sa)
	if got := heard(t, conn, f.ws); !slices.Equal(got, []string{"access_tokens", "service_accounts"}) {
		t.Errorf("a new key announced %v, want access_tokens and service_accounts", got)
	}
	exec(`DELETE FROM access_tokens WHERE token_hash = 'h-key'`)
	if got := heard(t, conn, f.ws); !slices.Equal(got, []string{"access_tokens"}) {
		t.Errorf("a revoked key announced %v, want access_tokens", got)
	}
}

func TestOnlyComingOnlineIsAnnounced(t *testing.T) {
	c := testConnection(t)
	conn := listenChanges(t, c)
	f := newStateFixture(t, c)
	heard(t, conn, f.ws)
	touch := func() []string {
		t.Helper()
		if err := c.Sys().TouchDaemons(t.Context(), []string{f.daemon}); err != nil {
			t.Fatalf("touch: %v", err)
		}
		return heard(t, conn, f.ws)
	}

	if got := touch(); !slices.Equal(got, []string{"daemons"}) {
		t.Errorf("the first stamp announced %v, want daemons", got)
	}
	if got := touch(); len(got) != 0 {
		t.Errorf("a heartbeat announced %v", got)
	}

	_, err := c.sysPool.Exec(t.Context(),
		`UPDATE daemons SET last_seen_at = NOW() - INTERVAL '1 minute' WHERE id = $1`, f.daemon)
	if err != nil {
		t.Fatalf("age the stamp: %v", err)
	}
	if got := touch(); !slices.Equal(got, []string{"daemons"}) {
		t.Errorf("a stamp after a minute of silence announced %v, want daemons", got)
	}
}
