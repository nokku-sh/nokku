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

	got, err := c.Sys().DashboardCounts(t.Context(), &DashboardCountsParams{WorkspaceID: f.ws, SeenAfter: seenAfter})
	if err != nil {
		t.Fatalf("counts: %v", err)
	}
	if got.Targets != 1 || got.TargetsOnline != 0 || got.TargetsManual != 0 || got.Members != 2 {
		t.Fatalf("offline daemon: got %+v", got)
	}

	touchDaemon(t, c, f.daemon, time.Now())
	got, err = c.Sys().DashboardCounts(t.Context(), &DashboardCountsParams{WorkspaceID: f.ws, SeenAfter: seenAfter})
	if err != nil {
		t.Fatalf("counts: %v", err)
	}
	if got.TargetsOnline != 1 {
		t.Errorf("online daemon: targets online = %d, want 1", got.TargetsOnline)
	}
}

func TestListOpenRecordings(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	open := uuid.NewV7().String()
	closed := uuid.NewV7().String()
	for _, id := range []string{open, closed} {
		if _, err := c.Sys().CreateRecording(t.Context(), &CreateRecordingParams{
			ID: id, WorkspaceID: f.ws, DaemonID: f.daemon, Username: "deploy", Key: []byte("key"),
		}); err != nil {
			t.Fatalf("create recording: %v", err)
		}
	}
	if _, err := c.Sys().
		SetRecordingComplete(t.Context(), &SetRecordingCompleteParams{ID: closed, Complete: true}); err != nil {
		t.Fatalf("close recording: %v", err)
	}
	params := &ListOpenRecordingsParams{WorkspaceID: f.ws, SeenAfter: time.Now().Add(-DaemonOnlineWindow)}

	// A daemon that stopped reporting may have died mid session.
	rows, err := c.Sys().ListOpenRecordings(t.Context(), params)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("offline daemon: got %d open recordings, want 0", len(rows))
	}

	touchDaemon(t, c, f.daemon, time.Now())
	rows, err = c.Sys().ListOpenRecordings(t.Context(), params)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != open || rows[0].DaemonName != "d" {
		t.Errorf("online daemon: got %+v, want only %s on d", rows, open)
	}
}

func TestAuditActivityByHour(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	for _, ok := range []bool{true, true, false} {
		if err := c.Sys().InsertAuditLog(t.Context(), &InsertAuditLogParams{
			WorkspaceID: &f.ws,
			ActorID:     f.owner,
			ActorKind:   "user",
			Action:      "UpdateTarget",
			Ok:          ok,
			Details:     []byte(`{}`),
		}); err != nil {
			t.Fatalf("insert audit log: %v", err)
		}
	}

	rows, err := c.Sys().AuditActivityByHour(t.Context(), &AuditActivityByHourParams{
		WorkspaceID: &f.ws,
		Since:       time.Now().Add(-24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("activity: %v", err)
	}
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
	if _, err := c.Sys().CreateRecording(t.Context(), &CreateRecordingParams{
		ID: id, WorkspaceID: f.ws, DaemonID: f.daemon, Username: "deploy", Key: []byte("key"),
	}); err != nil {
		t.Fatalf("create recording: %v", err)
	}
	if _, err := c.Sys().DeleteDaemon(t.Context(), f.daemon); err != nil {
		t.Fatalf("delete daemon: %v", err)
	}
	rec, err := c.Sys().GetRecording(t.Context(), id)
	if err != nil {
		t.Fatalf("the recording went with its daemon: %v", err)
	}
	if rec.DaemonID != nil || rec.DaemonName != "d" {
		t.Errorf("got daemon %v named %q, want none named d", rec.DaemonID, rec.DaemonName)
	}
}
