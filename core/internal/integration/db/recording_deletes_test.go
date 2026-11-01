//go:build integration

package db_test

import (
	"testing"
	"uuid"

	"github.com/jackc/pgerrcode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/db"
)

// However a recording row goes, its object is left to the sweeper.
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
	assert.True(t, queued(byApp), "a recording the app deleted was not queued")

	bySystem := record(f)
	_, err := c.sysPool.Exec(t.Context(), `DELETE FROM recordings WHERE id = $1`, bySystem.ID)
	require.NoError(t, err, "delete as system")
	assert.True(t, queued(bySystem), "a recording the system deleted was not queued")

	replaced := record(f)
	asOwner(t, c, f, func(q *db.Queries) error {
		_, err := q.FinishRecordingUpload(t.Context(), &db.FinishRecordingUploadParams{
			ID: replaced.ID, ObjectID: new(uuid.NewV7().String()), SizeBytes: 2,
		})
		return err
	})
	assert.True(t, queued(replaced), "an object a larger copy replaced was not queued")

	kept := record(f)
	asOwner(t, c, f, func(q *db.Queries) error {
		_, err := q.FinishRecordingUpload(t.Context(), &db.FinishRecordingUploadParams{ID: kept.ID, SizeBytes: 1})
		return err
	})
	assert.False(t, queued(kept), "an upload that kept the stored copy queued it for deletion")

	lost := &db.Recording{ObjectID: new(uuid.NewV7().String())}
	asOwner(t, c, f, func(q *db.Queries) error { return q.QueueLostRecordingObject(t.Context(), *lost.ObjectID) })
	assert.True(t, queued(lost), "an object that lost to a larger copy was not queued")

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

	err = pinnedConn(t, c, f.ws).QueryRow(t.Context(), `SELECT count(*) FROM recording_deletes`).Scan(new(int))
	assert.Equal(t, pgerrcode.InsufficientPrivilege, pgCode(err), "the app role read the queue")

	inWorkspace := record(f)
	asOwner(t, c, f, func(q *db.Queries) error { return q.DeleteWorkspace(t.Context(), f.ws) })
	assert.True(t, queued(inWorkspace), "the recordings of a workspace the app deleted were not queued")
	inOther := record(other)
	_, err = c.sysPool.Exec(t.Context(), `DELETE FROM workspaces WHERE id = $1`, other.ws)
	require.NoError(t, err, "delete a workspace as system")
	assert.True(t, queued(inOther), "the recordings of a workspace the system deleted were not queued")
}
