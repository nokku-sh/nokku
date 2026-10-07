package db

import (
	"testing"
	"time"
	"uuid"
)

func TestDashboardCounts(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	seenAfter := time.Now().Add(-DaemonOnlineWindow)

	// A second workspace, its rows must not show up in the counts.
	newStateFixture(t, c)
	counts := func() (got *DashboardCountsRow) {
		t.Helper()
		asOwner(t, c, f, func(q *Queries) (err error) {
			got, err = q.DashboardCounts(t.Context(), seenAfter)
			return err
		})
		return got
	}

	got := counts()
	if got.Targets != 1 || got.TargetsOnline != 0 || got.TargetsManual != 0 || got.Users != 2 {
		t.Fatalf("offline daemon: got %+v", got)
	}

	touchDaemon(t, c, f.daemon, time.Now())
	if got = counts(); got.TargetsOnline != 1 {
		t.Errorf("online daemon: targets online = %d, want 1", got.TargetsOnline)
	}
}

func TestListOpenRecordings(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	open := uuid.NewV7().String()
	closed := uuid.NewV7().String()
	asOwner(t, c, f, func(q *Queries) error {
		for _, id := range []string{open, closed} {
			if _, err := q.CreateRecording(t.Context(), &CreateRecordingParams{
				ID: id, DaemonID: f.daemon, Username: "deploy", Key: []byte("key"),
			}); err != nil {
				return err
			}
		}
		_, err := q.SetRecordingComplete(t.Context(), &SetRecordingCompleteParams{ID: closed, Complete: true})
		return err
	})
	seenAfter := time.Now().Add(-DaemonOnlineWindow)
	list := func() (rows []*ListOpenRecordingsRow) {
		t.Helper()
		asOwner(t, c, f, func(q *Queries) (err error) {
			rows, err = q.ListOpenRecordings(t.Context(), seenAfter)
			return err
		})
		return rows
	}

	// A daemon that stopped reporting may have died mid session.
	if rows := list(); len(rows) != 0 {
		t.Fatalf("offline daemon: got %d open recordings, want 0", len(rows))
	}

	touchDaemon(t, c, f.daemon, time.Now())
	if rows := list(); len(rows) != 1 || rows[0].ID != open || rows[0].DaemonName != "d" {
		t.Errorf("online daemon: got %+v, want only %s on d", rows, open)
	}
}

func TestAuditActivityByHour(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	for _, ok := range []bool{true, true, false} {
		if err := c.Sys().InsertAuditLog(t.Context(), &InsertAuditLogParams{
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

	var rows []*AuditActivityByHourRow
	asOwner(t, c, f, func(q *Queries) (err error) {
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

func touchDaemon(t *testing.T, c *Connection, id string, at time.Time) {
	t.Helper()
	if _, err := c.sysPool.Exec(t.Context(), `UPDATE daemons SET last_seen_at = $2 WHERE id = $1`, id, at); err != nil {
		t.Fatalf("touch daemon: %v", err)
	}
}

// A deleted server must not take the record of what was done on it along.
func TestRecordingOutlivesDaemon(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	id := uuid.NewV7().String()
	var rec *Recording
	asOwner(t, c, f, func(q *Queries) (err error) {
		if _, err = q.CreateRecording(t.Context(), &CreateRecordingParams{
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
