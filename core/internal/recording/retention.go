package recording

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/storage"
)

const (
	// An eviction only frees disk once its objects are gone.
	deleteEvery = 10 * time.Minute
	// maxFailedDeletes in a row ends a pass, the next one asks again.
	maxFailedDeletes = 3
)

func (s *Service) runRetention(ctx context.Context) {
	tick := time.Tick(12 * time.Hour)
	for {
		s.cleanup(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick:
		}
	}
}

// Apart from retention, a long queue must not hold up what expires.
func (s *Service) runDeletes(ctx context.Context) {
	tick := time.Tick(deleteEvery)
	for {
		if err := s.DeleteQueued(ctx); err != nil {
			slog.Error("deleting the objects of deleted recordings failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick:
		}
	}
}

// One transaction per workspace, so one that fails holds back no other.
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

// The expired recordings' objects go through the delete queue.
func (s *Service) expire(ctx context.Context, wsID string, cutoff time.Time) error {
	return s.conn.SysTx(ctx, func(q *db.Queries) error {
		locked, err := q.TryAdvisoryXactLock(ctx, "recording-retention:"+wsID)
		if err != nil || !locked {
			return err
		}
		return q.DeleteRecordingsBefore(ctx, &db.DeleteRecordingsBeforeParams{
			WorkspaceID: wsID,
			Cutoff:      cutoff,
		})
	})
}

// DeleteQueued holds no tx during a bucket call, a repeat delete does no harm.
func (s *Service) DeleteQueued(ctx context.Context) error {
	for failures := 0; failures < maxFailedDeletes; {
		item, err := s.conn.Sys().NextRecordingDelete(ctx)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		failed := s.deleteObject(ctx, item.WorkspaceID, item.ObjectID)
		if failed == nil {
			failures = 0
			err = s.conn.Sys().FinishRecordingDelete(ctx, item.ObjectID)
		} else {
			failures++
			slog.Error("delete recording object", "object_id", item.ObjectID, "error", failed)
			err = s.conn.Sys().DeferRecordingDelete(ctx, &db.DeferRecordingDeleteParams{
				ObjectID:  item.ObjectID,
				LastError: new(failed.Error()),
			})
		}
		if err != nil {
			return err
		}
	}
	return fmt.Errorf("stopped after %d failed deletes in a row", maxFailedDeletes)
}

func (s *Service) deleteObject(ctx context.Context, workspaceID, objectID string) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	return s.store.Delete(ctx, storage.RecordingPath(workspaceID, objectID))
}
