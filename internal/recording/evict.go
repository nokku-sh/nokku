package recording

import (
	"context"
	"log/slog"
	"time"

	"github.com/nokku-sh/nokku/internal/audit"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/storage"
)

// minEvictAge keeps a recording whatever the cap says. Without it a user
// could fill the cap to push out the recording of what they just did.
const minEvictAge = 24 * time.Hour

// EvictForBytes deletes the oldest recordings until inFlight fits. The upload
// in progress and anything younger than minEvictAge are never evicted, and an
// overage that cannot be cleared is accepted.
func (s *Service) EvictForBytes(
	ctx context.Context,
	workspaceID, recordingID string,
	inFlight int64,
) error {
	capBytes, err := s.limits.RecordingStorageBytes(ctx, workspaceID)
	if err != nil {
		// Fail open, a failed plan lookup never evicts recordings.
		slog.Warn("recording storage cap lookup failed", "error", err, "workspace_id", workspaceID)
		return nil
	}
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
			if v.ID == recordingID || time.Since(v.StartedAt) < minEvictAge {
				continue
			}
			if err := s.conn.WithWorkspace(ctx, func(q *db.Queries) error {
				return q.DeleteRecording(ctx, v.ID)
			}); err != nil {
				return err
			}
			// Best effort, a stray object goes with the workspace purge.
			if err := s.store.Delete(ctx, storage.RecordingPath(workspaceID, v.ID)); err != nil {
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
			// Audit it, an eviction removes evidence before its retention is up.
			if s.events != nil {
				if err := s.events.Append(ctx, &audit.Event{
					Timestamp:   time.Now().UTC(),
					WorkspaceID: workspaceID,
					Action:      "RecordingEvicted",
					ActorKind:   "system",
					Target:      v.ID,
					OK:          true,
					Details: map[string]any{
						"daemon_id":  v.DaemonID,
						"username":   v.Username,
						"started_at": v.StartedAt,
						"size_bytes": v.SizeBytes,
						"upload":     recordingID,
					},
				}); err != nil {
					slog.Warn("failed to write eviction audit log", "recording_id", v.ID, "error", err)
				}
			}
		}
		if freed == 0 {
			return nil
		}
		over -= freed
	}
	return nil
}
