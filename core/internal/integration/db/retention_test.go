//go:build integration

package db_test

import (
	"testing"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/core/internal/db"
)

// Retention takes what is older than the cutoff and keeps the rest, for the audit log and for recordings.
func TestRetentionDeletesExpired(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	old, fresh := time.Now().Add(-400*24*time.Hour), time.Now().Add(-time.Hour)
	for _, at := range []time.Time{old, fresh} {
		if _, err := pinnedConn(t, c, f.ws).Exec(t.Context(),
			`INSERT INTO audit.audit_logs (workspace_id, action, ok, timestamp) VALUES ($1, 'Retained', TRUE, $2)`,
			pgx.QueryExecModeSimpleProtocol, f.ws, at,
		); err != nil {
			t.Fatalf("seed audit row: %v", err)
		}
		if _, err := c.sysPool.Exec(t.Context(),
			`INSERT INTO recordings (id, object_id, workspace_id, daemon_name, username, key, started_at)
			VALUES ($1, $2, $3, 'd', 'deploy', '\x00', $4)`,
			pgx.QueryExecModeSimpleProtocol, uuid.NewV7().String(), uuid.NewV7().String(), f.ws, at,
		); err != nil {
			t.Fatalf("seed recording: %v", err)
		}
	}

	cutoff := time.Now().Add(-365 * 24 * time.Hour)
	if err := c.SysTx(t.Context(), func(q *db.Queries) error {
		if err := q.EnableAuditRetention(t.Context()); err != nil {
			return err
		}
		if _, err := q.DeleteWorkspaceAuditLogs(t.Context(), &db.DeleteWorkspaceAuditLogsParams{
			WorkspaceID: f.ws, Cutoff: cutoff,
		}); err != nil {
			return err
		}
		return q.DeleteRecordingsBefore(t.Context(), &db.DeleteRecordingsBeforeParams{
			WorkspaceID: f.ws, Cutoff: cutoff,
		})
	}); err != nil {
		t.Fatalf("retention: %v", err)
	}

	if n := count(t, c.sysPool, "SELECT COUNT(*) FROM recordings WHERE workspace_id = $1", f.ws); n != 1 {
		t.Errorf("%d recordings left, want the fresh one", n)
	}
	if n := count(t, c.sysPool, "SELECT COUNT(*) FROM recording_deletes WHERE workspace_id = $1", f.ws); n != 1 {
		t.Errorf("%d objects queued for deletion, want the expired one", n)
	}
	if n := count(t, c.sysPool,
		"SELECT COUNT(*) FROM audit.audit_logs WHERE workspace_id = $1 AND action = 'Retained'", f.ws); n != 1 {
		t.Errorf("%d audit rows left, want the fresh one", n)
	}
}
