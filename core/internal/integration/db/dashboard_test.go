//go:build integration

package db_test

import (
	"testing"
	"time"
	"uuid"

	"github.com/nokku-sh/nokku/core/internal/db"
)

func TestDashboardCounts(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)

	// A second workspace, its rows must not show up in the counts.
	newStateFixture(t, c)
	counts := func(connected ...string) (got *db.DashboardCountsRow) {
		t.Helper()
		asOwner(t, c, f, func(q *db.Queries) (err error) {
			got, err = q.DashboardCounts(t.Context(), connected)
			return err
		})
		return got
	}

	got := counts()
	if got.Targets != 1 || got.TargetsOnline != 0 || got.TargetsManual != 0 || got.Users != 2 {
		t.Fatalf("offline daemon: got %+v", got)
	}

	if got = counts(f.daemon); got.TargetsOnline != 1 {
		t.Errorf("online daemon: targets online = %d, want 1", got.TargetsOnline)
	}
}

func TestListOpenRecordings(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	open := uuid.NewV7().String()
	closed := uuid.NewV7().String()
	asOwner(t, c, f, func(q *db.Queries) error {
		for _, id := range []string{open, closed} {
			if _, err := q.CreateRecording(t.Context(), &db.CreateRecordingParams{
				ID: id, DaemonID: f.daemon, Username: "deploy", Key: []byte("key"),
			}); err != nil {
				return err
			}
		}
		_, err := q.FinishRecordingUpload(t.Context(), &db.FinishRecordingUploadParams{
			ID: closed, Complete: true, EndedAt: new(time.Now()),
		})
		return err
	})
	list := func(connected ...string) (rows []*db.ListOpenRecordingsRow) {
		t.Helper()
		asOwner(t, c, f, func(q *db.Queries) (err error) {
			rows, err = q.ListOpenRecordings(t.Context(), connected)
			return err
		})
		return rows
	}

	// A daemon that is not connected may have died mid session.
	if rows := list(); len(rows) != 0 {
		t.Fatalf("offline daemon: got %d open recordings, want 0", len(rows))
	}

	if rows := list(f.daemon); len(rows) != 1 || rows[0].ID != open || rows[0].DaemonName != "d" {
		t.Errorf("online daemon: got %+v, want only %s on d", rows, open)
	}
}

// The recordings page calls a session live by the same rule as the dashboard.
func TestListRecordingsMarksWhatIsLive(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	running, ended, stale := uuid.NewV7().String(), uuid.NewV7().String(), uuid.NewV7().String()
	asOwner(t, c, f, func(q *db.Queries) error {
		for _, id := range []string{running, ended, stale} {
			if _, err := q.CreateRecording(t.Context(), &db.CreateRecordingParams{
				ID: id, DaemonID: f.daemon, Username: "deploy", Key: []byte("key"),
			}); err != nil {
				return err
			}
		}
		_, err := q.FinishRecordingUpload(t.Context(), &db.FinishRecordingUploadParams{
			ID: ended, EndedAt: new(time.Now()),
		})
		return err
	})
	if _, err := c.sysPool.Exec(t.Context(),
		`UPDATE recordings SET started_at = NOW() - INTERVAL '25 hours' WHERE id = $1`, stale); err != nil {
		t.Fatalf("age a recording: %v", err)
	}
	live := func(connected ...string) map[string]bool {
		t.Helper()
		got := map[string]bool{}
		asOwner(t, c, f, func(q *db.Queries) error {
			rows, err := q.ListRecordings(t.Context(), &db.ListRecordingsParams{
				Connected: connected, Limit: new(int32(10)), Offset: new(int32(0)),
			})
			for _, row := range rows {
				got[row.Recording.ID] = row.Live
			}
			return err
		})
		return got
	}

	if got := live(); got[running] || got[ended] || got[stale] {
		t.Errorf("offline daemon: got %v, want nothing live", got)
	}
	if got := live(f.daemon); !got[running] || got[ended] || got[stale] {
		t.Errorf("online daemon: got %v, want only %s", got, running)
	}
}

func TestAuditActivityByHour(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	for _, ok := range []bool{true, true, false} {
		if err := c.Tenant().InsertAuditLog(pinned(t, f.ws), &db.InsertAuditLogParams{
			WorkspaceID: f.ws,
			ActorID:     f.owner,
			ActorKind:   "user",
			Action:      "UpdateTarget",
			Ok:          ok,
			Details:     []byte(`{}`),
		}); err != nil {
			t.Fatalf("insert audit log: %v", err)
		}
	}

	var rows []*db.AuditActivityByHourRow
	asOwner(t, c, f, func(q *db.Queries) (err error) {
		rows, err = q.AuditActivityByHour(t.Context(), time.Now().Add(-24*time.Hour))
		return err
	})
	var events, failures int32
	for _, r := range rows {
		events += r.Events
		failures += r.Failures
	}
	if events != 3 || failures != 1 {
		t.Errorf("got %d events and %d failures, want 3 and 1", events, failures)
	}
}

// A deleted server must not take the record of what was done on it along.
func TestRecordingOutlivesDaemon(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	id := uuid.NewV7().String()
	var rec *db.Recording
	asOwner(t, c, f, func(q *db.Queries) (err error) {
		if _, err = q.CreateRecording(t.Context(), &db.CreateRecordingParams{
			ID: id, DaemonID: f.daemon, Username: "deploy", Key: []byte("key"),
		}); err != nil {
			return err
		}
		if _, err = q.DeleteDaemon(t.Context(), f.daemon); err != nil {
			return err
		}
		// A missing row here means the recording went with its daemon.
		rec, err = q.GetRecording(t.Context(), id)
		return err
	})
	if rec.DaemonID != nil || rec.DaemonName != "d" {
		t.Errorf("got daemon %v named %q, want none named d", rec.DaemonID, rec.DaemonName)
	}
}
