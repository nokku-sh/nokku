package recording

import (
	"context"
	"log/slog"
	"time"

	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/storage"
)

func (s *Service) runSweeper(ctx context.Context) {
	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()

	s.cleanup(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.cleanup(ctx)
		}
	}
}

// cleanup gives each workspace a transaction of its own, so one that fails holds back no other.
func (s *Service) cleanup(ctx context.Context) {
	now := time.Now()
	workspaceIDs, err := s.conn.Sys().ListRecordingWorkspaceIDs(ctx)
	if err != nil {
		slog.Error("recording retention failed", "error", err)
		return
	}
	for _, wsID := range workspaceIDs {
		retentionDays, err := s.limits.RecordingRetentionDays(ctx, wsID)
		if err != nil {
			slog.Warn("recording retention skipped, plan lookup failed", "error", err, "workspace_id", wsID)
			continue
		}
		if retentionDays <= 0 {
			retentionDays = 7
		}
		if err := s.expire(ctx, wsID, now.AddDate(0, 0, -int(retentionDays))); err != nil {
			slog.Error("recording retention failed", "error", err, "workspace_id", wsID)
		}
	}
}

// expire deletes the recordings of wsID from before cutoff.
func (s *Service) expire(ctx context.Context, wsID string, cutoff time.Time) error {
	var expired []string
	err := s.conn.SysTx(ctx, func(q *db.Queries) error {
		locked, err := q.TryAdvisoryXactLock(ctx, "recording-retention:"+wsID)
		if err != nil || !locked {
			return err
		}
		rows, err := q.DeleteRecordingsBefore(ctx, &db.DeleteRecordingsBeforeParams{
			WorkspaceID: wsID,
			Cutoff:      cutoff,
		})
		if err != nil {
			return err
		}
		for _, rec := range rows {
			expired = append(expired, storage.RecordingPath(wsID, rec.ID))
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Objects go only after the rows are gone for good.
	for _, path := range expired {
		if err := s.store.Delete(ctx, path); err != nil {
			slog.Warn("delete expired recording object", "error", err, "path", path)
		}
	}
	return nil
}
