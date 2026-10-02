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

	if err := s.setupPartitions(ctx); err != nil {
		return nil, err
	}

	go s.runBackgroundJobs(ctx)
	return s, nil
}

// setupPartitions relies on audit.maintain_partitions running as the table owner.
func (s *Service) setupPartitions(ctx context.Context) error {
	return s.conn.Sys().MaintainAuditPartitions(ctx)
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
			if err := s.setupPartitions(ctx); err != nil {
				slog.Error("audit partition job failed", "error", err)
			}
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
			if wsID == nil {
				continue
			}
			retentionDays, err := s.entitlements.RetentionDays(ctx, *wsID)
			if err != nil {
				slog.Warn("audit retention skipped, plan lookup failed",
					"error", err, "workspace_id", *wsID)
				continue
			}
			retentionDays = min(retentionDays, maxRetentionDays)
			deleted, err := q.DeleteWorkspaceAuditLogs(ctx, &db.DeleteWorkspaceAuditLogsParams{
				WorkspaceID: wsID,
				Cutoff:      now.AddDate(0, 0, -int(retentionDays)),
			})
			if err != nil {
				return fmt.Errorf("workspace %s: %w", *wsID, err)
			}
			if deleted > 0 {
				slog.Debug("audit retention cleaned logs",
					"workspace_id", *wsID, "deleted", deleted,
					"retention_days", retentionDays)
			}
		}

		deleted, err := q.DeleteOrphanAuditLogs(ctx, now.AddDate(0, 0, -maxRetentionDays))
		if err != nil {
			return err
		}
		if deleted > 0 {
			slog.Debug("audit retention cleaned orphan logs", "deleted", deleted)
		}
		return nil
	})
	if err != nil {
		slog.Error("audit retention failed", "error", err)
	}
}
