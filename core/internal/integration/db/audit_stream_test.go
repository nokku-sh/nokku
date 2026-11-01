//go:build integration

package db_test

import (
	"testing"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/db"
)

// The cursor reads in order, skips what was sent, leaves the newest for later.
func TestAuditLogsAfterTheCursor(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	old := time.Now().Add(-time.Minute)
	_, err := pinnedConn(t, c, f.ws).Exec(t.Context(), `
		INSERT INTO audit.audit_logs (workspace_id, action, ok, timestamp) VALUES
			($1, 'First', TRUE, $2), ($1, 'Second', TRUE, $3), ($1, 'Fresh', TRUE, NOW());
	`, pgx.QueryExecModeSimpleProtocol, f.ws, old, old.Add(time.Second))
	require.NoError(t, err, "seed")

	after := func(ts time.Time, id string) []*db.AuditAuditLog {
		rows, err := c.Sys().ListAuditLogsAfter(t.Context(), &db.ListAuditLogsAfterParams{
			WorkspaceID: f.ws, CursorTs: ts, CursorID: id, MaxRows: 10,
		})
		require.NoError(t, err, "list after")
		return rows
	}

	rows := after(old.Add(-time.Hour), uuid.Nil().String())
	require.Len(t, rows, 2, "the fresh row waits")
	require.Equal(t, "First", rows[0].Action)
	require.Equal(t, "Second", rows[1].Action)
	rows = after(rows[0].Timestamp, rows[0].ID)
	require.Len(t, rows, 1, "after the first cursor")
	require.Equal(t, "Second", rows[0].Action)
}
