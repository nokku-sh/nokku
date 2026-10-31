// Package recording owns the recording lifecycle. It never sees a request or response type.
package recording

import (
	"context"

	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/crypto/kms"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/storage"
)

type Limits interface {
	RecordingRetentionDays(ctx context.Context, workspaceID string) (int64, error)
	RecordingStorageBytes(ctx context.Context, workspaceID string) (int64, error)
}

type Service struct {
	conn   *db.Connection
	keys   *kms.Keyset
	store  *storage.Storage
	limits Limits
	events *audit.Service
}

func New(
	ctx context.Context,
	conn *db.Connection,
	keys *kms.Keyset,
	store *storage.Storage,
	limits Limits,
	events *audit.Service,
) *Service {
	s := &Service{conn: conn, keys: keys, store: store, limits: limits, events: events}
	go s.runRetention(ctx)
	go s.runDeletes(ctx)
	return s
}
