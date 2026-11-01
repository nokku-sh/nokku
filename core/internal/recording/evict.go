package recording

import (
	"context"
	"log/slog"
	"time"

	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/db"
)

// minEvictAge stops anyone pushing out what they just did, whatever the cap.
const minEvictAge = 24 * time.Hour

// MakeRoom evicts the oldest recordings over the cap, and a failed lookup never
// refuses. Open uploads can pass the cap, which is only a stop for abuse.
func (s *Service) MakeRoom(ctx context.Context, workspaceID, recordingID string) bool {
	capBytes, err := s.limits.RecordingStorageBytes(ctx, workspaceID)
	if err != nil {
		slog.Warn("recording storage cap lookup failed", "error", err, "workspace_id", workspaceID)
		return true
	}
	if capBytes <= 0 {
		return true
	}
	used, err := s.conn.Tenant().SumRecordingBytes(ctx)
	if err != nil {
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
			deleted, err := s.conn.Tenant().DeleteRecording(ctx, v.ID)
			if err != nil {
				slog.Warn("recording eviction failed", "error", err, "workspace_id", workspaceID)
				return true
			}
			// Deleted since the list.
			if deleted == 0 {
				continue
			}
			over -= v.SizeBytes
			evicted++
			s.auditEviction(ctx, workspaceID, recordingID, v)
		}
		if evicted == 0 {
			return false
		}
	}
	return true
}

// An eviction removes evidence before its retention is up.
func (s *Service) auditEviction(ctx context.Context, workspaceID, upload string, v *db.Recording) {
	if s.events == nil {
		return
	}
	if err := s.events.Append(ctx, &audit.Event{
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
			"upload":     upload,
		},
	}); err != nil {
		slog.Warn("failed to write eviction audit log", "recording_id", v.ID, "error", err)
	}
}
