//go:build integration

package db_test

import (
	"testing"
	"time"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/integration/testenv"
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
	require.EqualValues(t, 1, got.Targets, "offline daemon")
	require.Zero(t, got.TargetsOnline, "offline daemon")
	require.Zero(t, got.TargetsManual, "offline daemon")
	require.EqualValues(t, 2, got.Users, "offline daemon")

	assert.EqualValues(t, 1, counts(f.daemon).TargetsOnline, "online daemon")
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
			ID: closed, Complete: true, EndedAt: new(time.Now()), ObjectID: new(uuid.NewV7().String()),
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
	require.Empty(t, list(), "offline daemon")

	rows := list(f.daemon)
	if assert.Len(t, rows, 1, "online daemon") {
		assert.Equal(t, open, rows[0].ID)
		assert.Equal(t, "d", rows[0].DaemonName)
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
	_, err := c.sysPool.Exec(t.Context(),
		`UPDATE recordings SET started_at = NOW() - INTERVAL '25 hours' WHERE id = $1`, stale)
	require.NoError(t, err, "age a recording")
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

	assert.Equal(t, map[string]bool{running: false, ended: false, stale: false}, live(), "offline daemon")
	assert.Equal(t, map[string]bool{running: true, ended: false, stale: false}, live(f.daemon), "online daemon")
}

func TestAuditActivityByHour(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	for _, ok := range []bool{true, true, false} {
		require.NoError(t, c.Tenant().InsertAuditLog(testenv.Pinned(t, f.ws), &db.InsertAuditLogParams{
			WorkspaceID: f.ws,
			ActorID:     f.owner,
			ActorKind:   "user",
			Action:      "UpdateTarget",
			Ok:          ok,
			Details:     []byte(`{}`),
		}), "insert audit log")
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
	assert.EqualValues(t, 3, events)
	assert.EqualValues(t, 1, failures)
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
	assert.Nil(t, rec.DaemonID)
	assert.Equal(t, "d", rec.DaemonName)
}
