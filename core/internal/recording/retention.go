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
	// deleteEvery is how often the objects of deleted recordings go. An eviction only frees disk once they do.
	deleteEvery = 10 * time.Minute
	// maxFailedDeletes in a row ends a pass, storage that is down is asked again on the next one.
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

// runDeletes is apart from retention, a long queue must not hold up what expires.
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

// expire deletes the recordings of wsID from before cutoff. Their objects go through the delete queue.
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

// DeleteQueued holds no transaction during a bucket call, and a delete that runs twice does no harm.
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

// deleteObject gives up on a bucket that hangs after a minute.
func (s *Service) deleteObject(ctx context.Context, workspaceID, objectID string) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	return s.store.Delete(ctx, storage.RecordingPath(workspaceID, objectID))
}
