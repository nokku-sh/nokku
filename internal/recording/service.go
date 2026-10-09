// Package recording owns the recording lifecycle. It never sees a request or response type.
package recording

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/nokku-sh/nokku/internal/audit"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/storage"
)

type Limits interface {
	RetentionDays(ctx context.Context, workspaceID string) (int64, error)
	RecordingStorageBytes(ctx context.Context, workspaceID string) (int64, error)
}

type Service struct {
	conn   *db.Connection
	store  *storage.Storage
	limits Limits
	events *audit.Service

	// A recording has one object. Uploads write it and the scrub rewrites it, mu guards who is at it.
	mu      sync.Mutex
	uploads map[string]int
	scrubs  map[string]*scrubRun
}

type scrubRun struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func New(
	ctx context.Context,
	conn *db.Connection,
	store *storage.Storage,
	limits Limits,
	events *audit.Service,
) *Service {
	s := &Service{
		conn: conn, store: store, limits: limits, events: events,
		uploads: map[string]int{}, scrubs: map[string]*scrubRun{},
	}
	go s.runSweeper(ctx)
	return s
}

// PurgeWorkspace runs detached, a large workspace outlives any request timeout.
func (s *Service) PurgeWorkspace(ctx context.Context, workspaceID string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Minute)
		defer cancel()
		if err := s.store.DeletePrefix(ctx, storage.RecordingPrefix(workspaceID)); err != nil {
			slog.Error("purge workspace recordings", "workspace_id", workspaceID, "error", err)
		}
	}()
}

// BeginUpload stops a scrub still rewriting an earlier try, its late commit would replace this upload.
func (s *Service) BeginUpload(recordingID string) (end func()) {
	s.mu.Lock()
	s.uploads[recordingID]++
	run := s.scrubs[recordingID]
	s.mu.Unlock()
	if run != nil {
		run.cancel()
		<-run.done
	}
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.uploads[recordingID]--; s.uploads[recordingID] == 0 {
			delete(s.uploads, recordingID)
		}
	}
}
