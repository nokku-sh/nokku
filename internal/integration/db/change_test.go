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

// silentTables are the sign-ins. They change all day and no list shows them
// to others, so no console hears about them.
var silentTables = []string{"credentials", "known_devices", "one_time_tokens", "sessions"}

// A new tenant table has to say whether a console hears its changes.
func TestEveryTenantTableAnnouncesOrIsSilent(t *testing.T) {
	c := testConnection(t)
	for _, table := range tenantTables(t, c) {
		got := count(t, c.sysPool, `
			SELECT COUNT(*) FROM pg_trigger
			WHERE tgrelid = ('public.' || $1)::regclass AND tgname IN ('notify_change', 'notify_change_update')`,
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
		"daemons", "principal_grants", "principals", "targets", "team_members", "teams", "users", "workspaces",
	}
	if got := heard(t, conn, f.ws); !slices.Equal(got, want) {
		t.Fatalf("seeding announced %v, want %v", got, want)
	}

	exec(`UPDATE targets SET name = 'renamed' WHERE id = $1`, f.target)
	if got := heard(t, conn, f.ws); !slices.Equal(got, []string{"targets"}) {
		t.Errorf("a rename announced %v, want targets", got)
	}

	exec(`DELETE FROM principal_grants WHERE principal_id = $1`, f.principal)
	if got := heard(t, conn, f.ws); !slices.Equal(got, []string{"principal_grants"}) {
		t.Errorf("a delete announced %v, want principal_grants", got)
	}

	exec(`UPDATE targets SET name = name WHERE id = $1`, f.target)
	exec(`UPDATE targets SET metadata = metadata || '{"last_manual_sync": "now"}' WHERE id = $1`, f.target)
	if got := heard(t, conn, f.ws); len(got) != 0 {
		t.Errorf("updates that change nothing a console shows announced %v", got)
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
