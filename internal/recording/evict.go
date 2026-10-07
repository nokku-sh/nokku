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

// MakeRoom reports whether the workspace can take an upload that is size
// bytes so far. Over the cap the oldest recordings are deleted first. The
// upload itself and anything younger than minEvictAge stay, so a workspace
// that took in more than its cap within that time is full and gets false.
// A failed lookup never refuses an upload.
func (s *Service) MakeRoom(ctx context.Context, workspaceID, recordingID string, size int64) bool {
	capBytes, err := s.limits.RecordingStorageBytes(ctx, workspaceID)
	if err != nil {
		slog.Warn("recording storage cap lookup failed", "error", err, "workspace_id", workspaceID)
		return true
	}
	if capBytes <= 0 {
		return true
	}
	var used int64
	if err := s.conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		// Uploads running side by side see each other through their rows.
		if size > 0 {
			err = q.SetRecordingSize(ctx, &db.SetRecordingSizeParams{ID: recordingID, SizeBytes: size})
			if err != nil {
				return err
			}
		}
		used, err = q.SumRecordingBytes(ctx)
		return err
	}); err != nil {
		slog.Warn("recording storage lookup failed", "error", err, "workspace_id", workspaceID)
		return true
	}
	over := used - capBytes
	for over > 0 {
		victims, err := s.conn.Tenant().OldestRecordings(ctx, new(int32(100)))
		if err != nil {
			slog.Warn("recording eviction failed", "error", err, "workspace_id", workspaceID)
			return true
		}
		evicted := 0
		for _, v := range victims {
			if over <= 0 {
				break
			}
			if v.ID == recordingID || time.Since(v.StartedAt) < minEvictAge {
				continue
			}
			if err := s.conn.Tenant().DeleteRecording(ctx, v.ID); err != nil {
				slog.Warn("recording eviction failed", "error", err, "workspace_id", workspaceID)
				return true
			}
			// Best effort, a stray object goes with the workspace purge.
			if err := s.store.Delete(ctx, storage.RecordingPath(workspaceID, v.ID)); err != nil {
				slog.Warn("delete evicted recording object", "recording_id", v.ID, "error", err)
			}
			over -= v.SizeBytes
			evicted++
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
		if evicted == 0 {
			return false
		}
	}
	return true
}
