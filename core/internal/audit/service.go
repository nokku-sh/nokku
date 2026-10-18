package audit

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/egress"
	"github.com/nokku-sh/nokku/core/internal/entitlement"
)

const (
	maxRetentionDays = 365
)

type Service struct {
	conn         *db.Connection
	entitlements *entitlement.Service
	// egress reaches the stream destinations a workspace chose.
	egress *http.Client
}

func New(ctx context.Context, conn *db.Connection, entitlements *entitlement.Service) (*Service, error) {
	client, err := egress.NewClient(streamTimeout)
	if err != nil {
		return nil, err
	}
	client.CheckRedirect = refuseRedirect
	s := &Service{conn: conn, entitlements: entitlements, egress: client}
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

func (s *Service) retentionCleanup(ctx context.Context) {
	now := time.Now()

	// The audit table refuses DELETE unless the transaction opts in.
	err := s.conn.SysTx(ctx, func(q *db.Queries) error {
		locked, err := q.TryAdvisoryXactLock(ctx, "audit-retention")
		if err != nil || !locked {
			return err
		}
		if err := q.EnableAuditRetention(ctx); err != nil {
			return err
		}

		workspaceIDs, err := q.ListWorkspaceAuditLogWorkspaceIDs(ctx)
		if err != nil {
			return err
		}
		for _, wsID := range workspaceIDs {
			retentionDays, err := s.entitlements.AuditRetentionDays(ctx, wsID)
			if err != nil {
				slog.Warn("audit retention skipped, plan lookup failed",
					"error", err, "workspace_id", wsID)
				continue
			}
			retentionDays = min(retentionDays, maxRetentionDays)
			if _, err := q.DeleteWorkspaceAuditLogs(ctx, &db.DeleteWorkspaceAuditLogsParams{
				WorkspaceID: wsID,
				Cutoff:      now.AddDate(0, 0, -int(retentionDays)),
			}); err != nil {
				return fmt.Errorf("workspace %s: %w", wsID, err)
			}
		}

		_, err = q.DeleteAuditLogsBefore(ctx, now.AddDate(0, 0, -maxRetentionDays))
		return err
	})
	if err != nil {
		slog.Error("audit retention failed", "error", err)
	}
}
