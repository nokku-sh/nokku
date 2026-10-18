//go:build integration

package db_test

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/core/internal/db"
)

// The cursor reads in a stable order, skips what was sent, and leaves the newest seconds for later.
func TestAuditLogsAfterTheCursor(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	old := time.Now().Add(-time.Minute)
	_, err := c.sysPool.Exec(t.Context(), `
		INSERT INTO audit.audit_logs (workspace_id, action, ok, timestamp) VALUES
			($1, 'First', TRUE, $2), ($1, 'Second', TRUE, $3), ($1, 'Fresh', TRUE, NOW());
	`, pgx.QueryExecModeSimpleProtocol, f.ws, old, old.Add(time.Second))
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	after := func(ts time.Time, id string) []*db.AuditAuditLog {
		rows, err := c.Sys().ListAuditLogsAfter(t.Context(), &db.ListAuditLogsAfterParams{
			WorkspaceID: f.ws, CursorTs: ts, CursorID: id, MaxRows: 10,
		})
		if err != nil {
			t.Fatalf("list after: %v", err)
		}
		return rows
	}

	rows := after(old.Add(-time.Hour), "00000000-0000-0000-0000-000000000000")
	if len(rows) != 2 || rows[0].Action != "First" || rows[1].Action != "Second" {
		t.Fatalf("want First and Second in order, the fresh row waits: got %d rows", len(rows))
	}
	rows = after(rows[0].Timestamp, rows[0].ID)
	if len(rows) != 1 || rows[0].Action != "Second" {
		t.Fatalf("after the first cursor: want Second only, got %d rows", len(rows))
	}
}
