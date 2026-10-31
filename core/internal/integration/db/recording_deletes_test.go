//go:build integration

package db_test

import (
	"testing"
	"uuid"

	"github.com/jackc/pgerrcode"

	"github.com/nokku-sh/nokku/core/internal/db"
)

// Every way a recording row goes leaves its object to the sweeper, whoever deletes it.
func TestDeletedRecordingsAreQueued(t *testing.T) {
	c := testConnection(t)
	f := newStateFixture(t, c)
	other := newStateFixture(t, c)
	record := func(f stateFixture) *db.Recording {
		t.Helper()
		var rec *db.Recording
		asOwner(t, c, f, func(q *db.Queries) (err error) {
			rec, err = q.CreateRecording(t.Context(), &db.CreateRecordingParams{
				ID: uuid.NewV7().String(), DaemonID: f.daemon, Username: "deploy", Key: []byte("k"),
			})
			if err != nil {
				return err
			}
			rec, err = q.FinishRecordingUpload(t.Context(), &db.FinishRecordingUploadParams{
				ID: rec.ID, ObjectID: new(uuid.NewV7().String()), SizeBytes: 1,
			})
			return err
		})
		return rec
	}
	queued := func(rec *db.Recording) bool {
		t.Helper()
		return count(t, c.sysPool, "SELECT COUNT(*) FROM recording_deletes WHERE object_id = $1", rec.ObjectID) > 0
	}

	byApp := record(f)
	asOwner(t, c, f, func(q *db.Queries) error {
		_, err := q.DeleteRecording(t.Context(), byApp.ID)
		return err
	})
	if !queued(byApp) {
		t.Error("a recording the app deleted was not queued")
	}

	bySystem := record(f)
	if _, err := c.sysPool.Exec(t.Context(), `DELETE FROM recordings WHERE id = $1`, bySystem.ID); err != nil {
		t.Fatalf("delete as system: %v", err)
	}
	if !queued(bySystem) {
		t.Error("a recording the system deleted was not queued")
	}

	replaced := record(f)
	asOwner(t, c, f, func(q *db.Queries) error {
		_, err := q.FinishRecordingUpload(t.Context(), &db.FinishRecordingUploadParams{
			ID: replaced.ID, ObjectID: new(uuid.NewV7().String()), SizeBytes: 2,
		})
		return err
	})
	if !queued(replaced) {
		t.Error("an object a larger copy replaced was not queued")
	}

	kept := record(f)
	asOwner(t, c, f, func(q *db.Queries) error {
		_, err := q.FinishRecordingUpload(t.Context(), &db.FinishRecordingUploadParams{ID: kept.ID, SizeBytes: 1})
		return err
	})
	if queued(kept) {
		t.Error("an upload that kept the stored copy queued it for deletion")
	}

	lost := &db.Recording{ObjectID: new(uuid.NewV7().String())}
	asOwner(t, c, f, func(q *db.Queries) error { return q.QueueLostRecordingObject(t.Context(), *lost.ObjectID) })
	if !queued(lost) {
		t.Error("an object that lost to a larger copy was not queued")
	}

	empty := uuid.NewV7().String()
	asOwner(t, c, f, func(q *db.Queries) error {
		if _, err := q.CreateRecording(t.Context(), &db.CreateRecordingParams{
			ID: empty, DaemonID: f.daemon, Username: "deploy", Key: []byte("k"),
		}); err != nil {
			return err
		}
		_, err := q.DeleteRecording(t.Context(), empty)
		return err
	})

	err := pinnedConn(t, c, f.ws).QueryRow(t.Context(), `SELECT count(*) FROM recording_deletes`).Scan(new(int))
	if code := pgCode(err); code != pgerrcode.InsufficientPrivilege {
		t.Errorf("the app role read the queue, error code %q", code)
	}

	inWorkspace := record(f)
	asOwner(t, c, f, func(q *db.Queries) error { return q.DeleteWorkspace(t.Context(), f.ws) })
	if !queued(inWorkspace) {
		t.Error("the recordings of a workspace the app deleted were not queued")
	}
	inOther := record(other)
	if _, err := c.sysPool.Exec(t.Context(), `DELETE FROM workspaces WHERE id = $1`, other.ws); err != nil {
		t.Fatalf("delete a workspace as system: %v", err)
	}
	if !queued(inOther) {
		t.Error("the recordings of a workspace the system deleted were not queued")
	}
}
