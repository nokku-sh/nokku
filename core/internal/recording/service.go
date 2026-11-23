// Package recording owns recordings, it never sees a request or response type.
package recording

import (
	"context"
	"log/slog"

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
}

func New(
	ctx context.Context,
	conn *db.Connection,
	keys *kms.Keyset,
	store *storage.Storage,
	limits Limits,
) *Service {
	s := &Service{conn: conn, keys: keys, store: store, limits: limits}
	go s.runRetention(ctx)
	go s.runDeletes(ctx)
	return s
}

// HasRoom is asked when an upload starts, so open uploads can pass the cap. A failed lookup never refuses.
func (s *Service) HasRoom(ctx context.Context, workspaceID string) bool {
	if !s.store.HasRoom() {
		slog.Warn("the disk of the recordings folder is nearly full, daemons keep their recordings until there is room")
		return false
	}
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
	return used <= capBytes
}
