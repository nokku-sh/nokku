//go:build integration

package db_test

import (
	"testing"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/core/internal/db"
)

// oldRows puts one audit row and one recording of f's workspace at when.
func oldRows(t *testing.T, c *conn, f stateFixture, when time.Time) (recording string) {
	t.Helper()
	recording = uuid.NewV7().String()
	_, err := c.sysPool.Exec(t.Context(), `
		INSERT INTO audit.audit_logs (workspace_id, action, ok, timestamp) VALUES ($1, 'Old', TRUE, $2);
		INSERT INTO recordings (id, workspace_id, daemon_name, username, key, started_at)
		VALUES ($3, $1, 'd', 'deploy', '\x00', $2);
	`, pgx.QueryExecModeSimpleProtocol, f.ws, when, recording)
	if err != nil {
		t.Fatalf("seed old rows: %v", err)
	}
	return recording
}

func oldAuditRows(t *testing.T, c *conn, f stateFixture) int {
	t.Helper()
	var n int
	if err := c.sysPool.QueryRow(t.Context(),
		`SELECT count(*) FROM audit.audit_logs WHERE workspace_id = $1 AND action = 'Old'`, f.ws,
	).Scan(&n); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	return n
}

func purge(t *testing.T, c *conn, f stateFixture, cutoff time.Time) (recordings int) {
	t.Helper()
	err := c.SysTx(t.Context(), func(q *db.Queries) error {
		if err := q.EnableAuditRetention(t.Context()); err != nil {
			return err
		}
		if _, err := q.DeleteWorkspaceAuditLogs(t.Context(), &db.DeleteWorkspaceAuditLogsParams{
			WorkspaceID: f.ws, Cutoff: cutoff,
		}); err != nil {
			return err
		}
		if _, err := q.DeleteAuditLogsBefore(t.Context(), cutoff); err != nil {
			return err
		}
		gone, err := q.DeleteRecordingsBefore(t.Context(), &db.DeleteRecordingsBeforeParams{
			WorkspaceID: f.ws, Cutoff: cutoff,
		})
		recordings = len(gone)
		return err
	})
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	return recordings
}

func TestLegalHoldOutlastsRetention(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	when := time.Now().Add(-400 * 24 * time.Hour)
	recording := oldRows(t, c, f, when)

	var hold *db.LegalHold
	asOwner(t, c, f, func(q *db.Queries) (err error) {
		hold, err = q.CreateLegalHold(t.Context(), &db.CreateLegalHoldParams{
			Reason:   "incident 42",
			StartsAt: when.Add(-time.Hour),
			EndsAt:   new(when.Add(time.Hour)),
		})
		return err
	})

	cutoff := time.Now().Add(-365 * 24 * time.Hour)
	if n := purge(t, c, f, cutoff); n != 0 {
		t.Fatalf("retention deleted %d held recordings", n)
	}
	if oldAuditRows(t, c, f) != 1 {
		t.Fatal("retention deleted a held audit row")
	}

	asOwner(t, c, f, func(q *db.Queries) error {
		victims, err := q.OldestRecordings(t.Context(), new(int32(100)))
		if err != nil {
			return err
		}
		for _, v := range victims {
			if v.ID == recording {
				t.Fatal("a held recording was offered for eviction")
			}
		}
		deleted, err := q.DeleteRecording(t.Context(), recording)
		if err != nil {
			return err
		}
		if deleted != 0 {
			t.Fatal("a held recording was deleted by hand")
		}
		held, err := q.RecordingHeld(t.Context(), recording)
		if err != nil || !held {
			t.Fatalf("held = %v (%v), want true", held, err)
		}
		_, err = q.DeleteLegalHold(t.Context(), hold.ID)
		return err
	})

	if n := purge(t, c, f, cutoff); n != 1 {
		t.Fatalf("after release: retention deleted %d recordings, want 1", n)
	}
	if oldAuditRows(t, c, f) != 0 {
		t.Fatal("after release: the audit row is still there")
	}
}

// An open hold keeps everything from its start on.
func TestOpenLegalHoldKeepsWhatFollows(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	when := time.Now().Add(-100 * 24 * time.Hour)
	oldRows(t, c, f, when)

	asOwner(t, c, f, func(q *db.Queries) error {
		_, err := q.CreateLegalHold(t.Context(), &db.CreateLegalHoldParams{
			Reason:   "open investigation",
			StartsAt: when.Add(-time.Minute),
		})
		return err
	})

	if n := purge(t, c, f, time.Now().Add(-30*24*time.Hour)); n != 0 {
		t.Fatalf("retention deleted %d recordings under an open hold", n)
	}
	if oldAuditRows(t, c, f) != 1 {
		t.Fatal("retention deleted an audit row under an open hold")
	}
}

// Deleting the workspace would take its held recordings and the hold itself, and leave its audit rows unprotected.
func TestLegalHoldKeepsTheWorkspace(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)

	var hold *db.LegalHold
	asOwner(t, c, f, func(q *db.Queries) (err error) {
		hold, err = q.CreateLegalHold(t.Context(), &db.CreateLegalHoldParams{
			Reason:   "incident 7",
			StartsAt: time.Now().Add(-time.Hour),
		})
		return err
	})

	asOwner(t, c, f, func(q *db.Queries) error {
		deleted, err := q.DeleteWorkspace(t.Context(), f.ws)
		if err != nil {
			return err
		}
		if deleted != 0 {
			t.Fatal("a workspace under a legal hold was deleted")
		}
		_, err = q.DeleteLegalHold(t.Context(), hold.ID)
		return err
	})

	asOwner(t, c, f, func(q *db.Queries) error {
		deleted, err := q.DeleteWorkspace(t.Context(), f.ws)
		if deleted != 1 {
			t.Fatalf("after release: deleted %d workspaces, want 1", deleted)
		}
		return err
	})
}
