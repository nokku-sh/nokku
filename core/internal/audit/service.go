package audit

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
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
	// sending holds the ids of streams with a delivery in flight.
	sending sync.Map
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

// retentionCleanup gives each workspace a transaction of its own, so one that fails holds back no other.
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
		err = s.deleteAuditLogs(ctx, "audit-retention:"+wsID, func(q *db.Queries) error {
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

	// Nothing outlives the longest plan, the rows of a deleted workspace included.
	err = s.deleteAuditLogs(ctx, "audit-retention", func(q *db.Queries) error {
		_, err := q.DeleteAuditLogsBefore(ctx, now.AddDate(0, 0, -maxRetentionDays))
		return err
	})
	if err != nil {
		slog.Error("audit retention failed", "error", err)
	}
}

// deleteAuditLogs runs del alone in a transaction. The audit table refuses DELETE unless the transaction opts in.
func (s *Service) deleteAuditLogs(ctx context.Context, lock string, del func(*db.Queries) error) error {
	return s.conn.SysTx(ctx, func(q *db.Queries) error {
		locked, err := q.TryAdvisoryXactLock(ctx, lock)
		if err != nil || !locked {
			return err
		}
		if err := q.EnableAuditRetention(ctx); err != nil {
			return err
		}
		return del(q)
	})
}
