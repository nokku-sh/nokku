package recording

import (
	"context"
	"log/slog"

	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/storage"
)

// EvictForBytes deletes the oldest recordings until inFlight fits. The upload
// in progress is never evicted, and an overage that cannot be cleared is
// accepted.
func (s *Service) EvictForBytes(
	ctx context.Context,
	workspaceID, recordingID string,
	inFlight int64,
) error {
	capBytes := s.limits.RecordingStorageBytes(ctx, workspaceID)
	if capBytes <= 0 {
		return nil
	}
	var used int64
	if err := s.conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		used, err = q.SumRecordingBytes(ctx, workspaceID)
		return err
	}); err != nil {
		// Fail open, bookkeeping problems never block an upload.
		slog.Warn("recording storage lookup failed", "error", err, "workspace_id", workspaceID)
		return nil
	}
	over := max(used+inFlight-capBytes, 0)
	for over > 0 {
		var victims []*db.Recording
		if err := s.conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
			victims, err = q.OldestRecordings(ctx, &db.OldestRecordingsParams{
				WorkspaceID: workspaceID,
				Limit:       new(int32(100)),
			})
			return err
		}); err != nil {
			return err
		}
		var freed int64
		for _, v := range victims {
			if v.ID == recordingID {
				continue
			}
			if err := s.conn.WithWorkspace(ctx, func(q *db.Queries) error {
				return q.DeleteRecording(ctx, v.ID)
			}); err != nil {
				return err
			}
			// Best effort, a stray object is swept by the workspace wipe.
			if err := s.store.Delete(
				ctx,
				storage.RecordingPath(workspaceID, v.ID),
			); err != nil {
				slog.Warn("delete evicted recording object", "recording_id", v.ID, "error", err)
			}
			freed += v.SizeBytes
			slog.Info(
				"evicted recording over storage cap",
				"recording_id",
				v.ID,
				"size",
				v.SizeBytes,
			)
		}
		if freed == 0 {
			return nil
		}
		over -= freed
	}
	return nil
}
