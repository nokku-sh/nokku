package audit

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/nokku-sh/nokku/core/internal/crypto/kms"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/egress"
	"github.com/nokku-sh/nokku/core/internal/entitlement"
)

const (
	maxRetentionDays = 365
)

type Service struct {
	conn         *db.Connection
	keys         *kms.Keyset
	entitlements *entitlement.Service
	// egress reaches the stream destinations a workspace chose.
	egress *http.Client
	// sending holds the ids of streams with a delivery in flight.
	sending sync.Map
}

func New(
	ctx context.Context,
	conn *db.Connection,
	keys *kms.Keyset,
	entitlements *entitlement.Service,
	hosted bool,
) (*Service, error) {
	client := egress.NewClient(streamTimeout, hosted)
	client.CheckRedirect = refuseRedirect
	s := &Service{conn: conn, keys: keys, entitlements: entitlements, egress: client}
	go s.runBackgroundJobs(ctx)
	go s.streamLoop(ctx)
	return s, nil
}

func (s *Service) runBackgroundJobs(ctx context.Context) {
	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()

	s.retentionCleanup(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.retentionCleanup(ctx)
		}
	}
}

// One transaction per workspace, so one that fails holds back no other.
func (s *Service) retentionCleanup(ctx context.Context) {
	now := time.Now()
	workspaceIDs, err := s.conn.Sys().ListWorkspaceAuditLogWorkspaceIDs(ctx)
	if err != nil {
		slog.Error("audit retention failed", "error", err)
		return
	}
	for _, wsID := range workspaceIDs {
		retentionDays, err := s.entitlements.AuditRetentionDays(ctx, wsID)
		if err != nil {
			slog.Warn("audit retention skipped, plan lookup failed", "error", err, "workspace_id", wsID)
			continue
		}
		retentionDays = min(retentionDays, maxRetentionDays)
		err = s.deleteAuditLogs(ctx, func(q *db.Queries) error {
			_, err := q.DeleteWorkspaceAuditLogs(ctx, &db.DeleteWorkspaceAuditLogsParams{
				WorkspaceID: wsID,
				Cutoff:      now.AddDate(0, 0, -int(retentionDays)),
			})
			return err
		})
		if err != nil {
			slog.Error("audit retention failed", "error", err, "workspace_id", wsID)
		}
	}

	// Nothing outlives the longest plan, a deleted workspace's rows included.
	err = s.deleteAuditLogs(ctx, func(q *db.Queries) error {
		_, err := q.DeleteAuditLogsBefore(ctx, now.AddDate(0, 0, -maxRetentionDays))
		return err
	})
	if err != nil {
		slog.Error("audit retention failed", "error", err)
	}
}

// The audit table refuses DELETE unless the transaction opts in.
func (s *Service) deleteAuditLogs(ctx context.Context, del func(*db.Queries) error) error {
	return s.conn.SysTx(ctx, func(q *db.Queries) error {
		if err := q.EnableAuditRetention(ctx); err != nil {
			return err
		}
		return del(q)
	})
}
