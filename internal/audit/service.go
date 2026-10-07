// Package audit contains the audit service.
package audit

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/entitlement"
)

const (
	maxRetentionDays = 365
)

type Service struct {
	conn         *db.Connection
	entitlements *entitlement.Service
	sinks        []sink
}

func New(
	ctx context.Context,
	conn *db.Connection,
	entitlements *entitlement.Service,
) (*Service, error) {
	webhooks, err := newWebhookSink(ctx, conn, entitlements)
	if err != nil {
		return nil, err
	}
	s := &Service{
		conn:         conn,
		entitlements: entitlements,
		sinks:        []sink{newPostgresSink(conn), webhooks},
	}

	go s.runBackgroundJobs(ctx)
	return s, nil
}

func (s *Service) runBackgroundJobs(ctx context.Context) {
	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()

	s.retentionCleanup(ctx) // initial cleanup

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
	err := s.conn.WithTx(ctx, func(q *db.Queries) error {
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
			retentionDays, err := s.entitlements.RetentionDays(ctx, wsID)
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
