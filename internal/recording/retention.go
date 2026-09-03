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

	// Retention deletes across every workspace: system transaction
	// (BYPASSRLS), single-flight via advisory lock like audit retention.
	tx, err := s.conn.AdminPool.Begin(ctx)
	if err != nil {
		slog.Error("recording retention failed to begin transaction", "error", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var locked bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtext('recording-retention'))`).
		Scan(&locked); err != nil {
		slog.Error("recording retention failed to acquire lock", "error", err)
		return
	}
	if !locked {
		slog.Debug("recording retention skipped, another instance running")
		return
	}

	q := db.New(tx)

	workspaceIDs, err := q.ListRecordingWorkspaceIDs(ctx)
	if err != nil {
		slog.Error("recording retention failed to list workspaces", "error", err)
		return
	}

	for _, wsID := range workspaceIDs {
		retentionDays := s.limits.RetentionDays(ctx, wsID)
		if retentionDays <= 0 {
			retentionDays = 7
		}
		cutoff := now.AddDate(0, 0, -int(retentionDays))

		expired, err := q.DeleteRecordingsBefore(ctx, &db.DeleteRecordingsBeforeParams{
			WorkspaceID: wsID,
			Cutoff:      cutoff,
		})
		if err != nil {
			slog.Error("recording retention delete failed",
				"error", err, "workspace_id", wsID)
			continue
		}
		if len(expired) == 0 {
			continue
		}

		// Objects are best-effort: a stray object without a row is
		// invisible and swept by the workspace wipe.
		for _, rec := range expired {
			if err := s.store.Delete(
				ctx,
				storage.RecordingPath(wsID, rec.ID),
			); err != nil {
				slog.Warn("delete expired recording object",
					"error", err, "recording_id", rec.ID)
			}
		}
		slog.Info("expired recordings removed",
			"workspace_id", wsID, "count", len(expired))
	}

	if err := tx.Commit(ctx); err != nil {
		slog.Error("recording retention failed to commit", "error", err)
	}
}
