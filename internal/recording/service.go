// Package recording owns the recording lifecycle. It never sees a request or
// response type.
package recording

import (
	"context"
	"log/slog"
	"time"

	"github.com/nokku-sh/nokku/internal/audit"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/storage"
)

type Limits interface {
	RetentionDays(ctx context.Context, workspaceID string) (int64, error)
	RecordingStorageBytes(ctx context.Context, workspaceID string) (int64, error)
}

type EventSink interface {
	Append(ctx context.Context, event *audit.Event) error
}

type Service struct {
	conn   *db.Connection
	store  *storage.Storage
	limits Limits
	events EventSink
}

func New(
	ctx context.Context,
	conn *db.Connection,
	store *storage.Storage,
	limits Limits,
	events EventSink,
) *Service {
	s := &Service{conn: conn, store: store, limits: limits, events: events}
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
