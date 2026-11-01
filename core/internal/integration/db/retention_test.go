//go:build integration

package db_test

import (
	"testing"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/db"
)

// Retention takes what is older than the cutoff, in audit log and recordings.
func TestRetentionDeletesExpired(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	old, fresh := time.Now().Add(-400*24*time.Hour), time.Now().Add(-time.Hour)
	for _, at := range []time.Time{old, fresh} {
		_, err := pinnedConn(t, c, f.ws).Exec(t.Context(),
			`INSERT INTO audit.audit_logs (workspace_id, action, ok, timestamp) VALUES ($1, 'Retained', TRUE, $2)`,
			pgx.QueryExecModeSimpleProtocol, f.ws, at,
		)
		require.NoError(t, err, "seed audit row")
		_, err = c.sysPool.Exec(t.Context(),
			`INSERT INTO recordings (id, object_id, workspace_id, daemon_name, username, key, started_at)
			VALUES ($1, $2, $3, 'd', 'deploy', '\x00', $4)`,
			pgx.QueryExecModeSimpleProtocol, uuid.NewV7().String(), uuid.NewV7().String(), f.ws, at,
		)
		require.NoError(t, err, "seed recording")
	}

	cutoff := time.Now().Add(-365 * 24 * time.Hour)
	require.NoError(t, c.SysTx(t.Context(), func(q *db.Queries) error {
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
	}), "retention")

	assert.EqualValues(t, 1,
		count(t, c.sysPool, "SELECT COUNT(*) FROM recordings WHERE workspace_id = $1", f.ws),
		"recordings left, want the fresh one")
	assert.EqualValues(t, 1,
		count(t, c.sysPool, "SELECT COUNT(*) FROM recording_deletes WHERE workspace_id = $1", f.ws),
		"objects queued for deletion, want the expired one")
	assert.EqualValues(t, 1,
		count(t, c.sysPool,
			"SELECT COUNT(*) FROM audit.audit_logs WHERE workspace_id = $1 AND action = 'Retained'", f.ws),
		"audit rows left, want the fresh one")
}

// An enabled stream holds what it has not sent. A paused one gives that up, and
// nothing outlives the longest retention.
func TestRetentionWaitsForEnabledStreams(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	now := time.Now()
	seed := func(age time.Duration) {
		t.Helper()
		_, err := pinnedConn(t, c, f.ws).Exec(t.Context(),
			`INSERT INTO audit.audit_logs (workspace_id, action, ok, timestamp) VALUES ($1, 'Streamed', TRUE, $2)`,
			pgx.QueryExecModeSimpleProtocol, f.ws, now.Add(-age),
		)
		require.NoError(t, err, "seed audit row")
	}
	const day = 24 * time.Hour
	seed(200 * day) // sent, the cursor is past it
	seed(120 * day) // past retention, not sent yet
	seed(400 * day)

	var stream string
	require.NoError(t, c.sysPool.QueryRow(t.Context(),
		`INSERT INTO audit_streams (workspace_id, kind, url, secret, enabled, cursor_ts)
		VALUES ($1, 'webhook', 'https://siem.example', '\x00', TRUE, $2) RETURNING id`,
		f.ws, now.Add(-150*day),
	).Scan(&stream), "seed stream")

	retain := func() {
		t.Helper()
		require.NoError(t, c.SysTx(t.Context(), func(q *db.Queries) error {
			if err := q.EnableAuditRetention(t.Context()); err != nil {
				return err
			}
			_, err := q.DeleteWorkspaceAuditLogs(t.Context(), &db.DeleteWorkspaceAuditLogsParams{
				WorkspaceID: f.ws, Cutoff: now.Add(-90 * day),
			})
			return err
		}), "retention")
	}
	left := func() int64 {
		t.Helper()
		return count(t, c.sysPool,
			"SELECT COUNT(*) FROM audit.audit_logs WHERE workspace_id = $1 AND action = 'Streamed'", f.ws)
	}

	retain()
	assert.EqualValues(t, 1, left(), "want only the row the stream has not sent")

	_, err := c.sysPool.Exec(t.Context(), `UPDATE audit_streams SET enabled = FALSE WHERE id = $1`, stream)
	require.NoError(t, err, "pause stream")
	retain()
	assert.EqualValues(t, 0, left(), "a paused stream held back retention")
}
