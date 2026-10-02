package recording

import (
	"context"
	"log/slog"
	"time"

	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/storage"
)

func (s *Service) runSweeper(ctx context.Context) {
	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()

	s.cleanup(ctx) // initial cleanup

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.cleanup(ctx)
		}
	}
}

func (s *Service) cleanup(ctx context.Context) {
	now := time.Now()

	var expired []string
	err := s.conn.WithTx(ctx, func(q *db.Queries) error {
		locked, err := q.TryAdvisoryXactLock(ctx, "recording-retention")
		if err != nil || !locked {
			return err
		}
		workspaceIDs, err := q.ListRecordingWorkspaceIDs(ctx)
		if err != nil {
			return err
		}
		for _, wsID := range workspaceIDs {
			retentionDays, err := s.limits.RetentionDays(ctx, wsID)
			if err != nil {
				slog.Warn("recording retention skipped, plan lookup failed",
					"error", err, "workspace_id", wsID)
				continue
			}
			if retentionDays <= 0 {
				retentionDays = 7
			}
			rows, err := q.DeleteRecordingsBefore(ctx, &db.DeleteRecordingsBeforeParams{
				WorkspaceID: wsID,
				Cutoff:      now.AddDate(0, 0, -int(retentionDays)),
			})
			if err != nil {
				return err
			}
			for _, rec := range rows {
				expired = append(expired, storage.RecordingPath(wsID, rec.ID))
			}
		}
		return nil
	})
	if err != nil {
		slog.Error("recording retention failed", "error", err)
		return
	}

	// Objects go only after the rows are gone for good.
	for _, path := range expired {
		if err := s.store.Delete(ctx, path); err != nil {
			slog.Warn("delete expired recording object", "error", err, "path", path)
		}
	}
	if len(expired) > 0 {
		slog.Info("expired recordings removed", "count", len(expired))
	}
}
