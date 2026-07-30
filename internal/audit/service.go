// Package audit contains the audit service
package audit

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/entitlement"
)

const (
	// OrphanLogRetentionDays is the compliance hard cap for user-level
	// (non-workspace) audit logs. All such logs older than this are purged.
	OrphanLogRetentionDays = 365

	// defaultRetentionDays is the fallback when a workspace has no subscription
	// or the plan doesn't define a retention policy.
	defaultRetentionDays = 7

	// maxRetentionDays is the absolute ceiling for any workspace.
	maxRetentionDays = 365
)

type Service struct {
	conn         *db.Connection
	entitlements *entitlement.Service
}

func New(ctx context.Context, conn *db.Connection, ent *entitlement.Service) (*Service, error) {
	s := &Service{conn: conn, entitlements: ent}

	// Ensure the base audit schema and partitions exist
	if err := s.Migrate(ctx); err != nil {
		return nil, err
	}
	if err := s.ensurePartitions(ctx); err != nil {
		return nil, err
	}
	// Run retention cleanup on startup too, not just on the ticker
	s.retentionCleanup(ctx)

	go s.runBackgroundJobs(ctx)
	return s, nil
}

func (s *Service) ensurePartitions(ctx context.Context) error {
	now := time.Now()

	// Normalize to the 1st of the current month to prevent AddDate wraparound issues
	currentMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)

	tx, err := s.conn.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Try to acquire the transaction-level lock
	var locked bool
	err = tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtext('audit-partitions'))`).
		Scan(&locked)
	if err != nil {
		return fmt.Errorf("failed to query advisory lock: %w", err)
	}
	if !locked {
		slog.Debug("Another instance is managing partitions, skipping.")
		return nil
	}

	// Create for current month
	if err := s.createPartitionForMonth(ctx, tx, currentMonth); err != nil {
		return err
	}

	// Create for next month
	nextMonth := currentMonth.AddDate(0, 1, 0)
	if err := s.createPartitionForMonth(ctx, tx, nextMonth); err != nil {
		return err
	}

	// Drop old partitions (older than 6 months)
	sixMonthsAgo := currentMonth.AddDate(0, -6, 0)
	if err := s.dropPartitionsBefore(ctx, tx, sixMonthsAgo); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (s *Service) createPartitionForMonth(ctx context.Context, tx pgx.Tx, t time.Time) error {
	tableName := t.Format("audit_logs_y2006m01")
	start := time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)

	query := fmt.Sprintf(
		`CREATE TABLE IF NOT EXISTS "audit".%q PARTITION OF "audit"."audit_logs" FOR VALUES FROM ('%s') TO ('%s');`,
		tableName,
		start.Format(time.RFC3339),
		end.Format(time.RFC3339),
	)

	_, err := tx.Exec(ctx, query)
	if err != nil {
		slog.Error("Failed to create partition", "table", tableName, "error", err)
		return err
	}
	return nil
}

func (s *Service) dropPartitionsBefore(ctx context.Context, tx pgx.Tx, t time.Time) error {
	// Query to find all partitions of audit.audit_logs
	query := `
		SELECT inhrelid::regclass::text 
		FROM pg_inherits 
		WHERE inhparent = 'audit.audit_logs'::regclass;`

	rows, err := tx.Query(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()

	thresholdName := t.Format("audit_logs_y2006m01")

	for rows.Next() {
		var partitionName string
		if err := rows.Scan(&partitionName); err != nil {
			return err
		}

		// Strip the schema name if present (e.g., "audit.audit_logs_...")
		parts := strings.Split(partitionName, ".")
		shortName := parts[len(parts)-1]

		// REMOVE any double quotes injected by Postgres regclass
		shortName = strings.Trim(shortName, "\"")

		// Simple string comparison e.g., "audit_logs_y2025m01" < "audit_logs_y2025m10"
		if shortName < thresholdName {
			dropQuery := `DROP TABLE IF EXISTS ` + partitionName + `;`

			if _, err := tx.Exec(ctx, dropQuery); err != nil {
				slog.Error("Failed to drop old partition", "table", partitionName, "error", err)
				return err
			}
		}
	}
	return nil
}

func (s *Service) runBackgroundJobs(ctx context.Context) {
	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.ensurePartitions(ctx); err != nil {
				slog.Error("Partition manager failed", "error", err)
			}
			s.retentionCleanup(ctx)
		}
	}
}

func (s *Service) retentionCleanup(ctx context.Context) {
	now := time.Now()

	tx, err := s.conn.Pool.Begin(ctx)
	if err != nil {
		slog.Error("Retention: failed to begin transaction", "error", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var locked bool
	err = tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtext('audit-retention'))`).
		Scan(&locked)
	if err != nil {
		slog.Error("Retention: failed to query advisory lock", "error", err)
		return
	}
	if !locked {
		slog.Debug("Retention: another instance is running cleanup, skipping.")
		return
	}

	q := db.New(tx)

	// --- Per-workspace audit log cleanup ---

	workspaceIDs, err := q.ListWorkspaceAuditLogWorkspaceIDs(ctx)
	if err != nil {
		slog.Error("Retention: failed to list workspace IDs", "error", err)
		return
	}

	for _, wsID := range workspaceIDs {
		if wsID == nil {
			continue
		}
		retentionDays := int64(defaultRetentionDays)
		hardcap := int64(maxRetentionDays)

		if v := s.entitlements.Int(ctx, *wsID, entitlement.ValueAuditRetentionDays, 0); v > 0 {
			retentionDays = v
		}

		if retentionDays > hardcap {
			retentionDays = hardcap
		}

		cutoff := now.AddDate(0, 0, -int(retentionDays))

		deleted, err := q.DeleteWorkspaceAuditLogs(ctx, &db.DeleteWorkspaceAuditLogsParams{
			WorkspaceID: wsID,
			Cutoff:      cutoff,
		})
		if err != nil {
			slog.Error("Retention: failed to delete old audit logs",
				"workspace_id", wsID, "error", err)
			continue
		}
		if deleted > 0 {
			slog.Debug("Retention: cleaned up workspace audit logs",
				"workspace_id", wsID, "deleted", deleted,
				"retention_days", retentionDays)
		}
	}

	// --- Orphan (non-workspace) audit log cleanup ---

	orphanCutoff := now.AddDate(0, 0, -OrphanLogRetentionDays)
	deleted, err := q.DeleteOrphanAuditLogs(ctx, orphanCutoff)
	if err != nil {
		slog.Error("Retention: failed to delete orphan audit logs", "error", err)
		return
	}
	if deleted > 0 {
		slog.Debug("Retention: cleaned up orphan audit logs", "deleted", deleted)
	}

	if err := tx.Commit(ctx); err != nil {
		slog.Error("Retention: failed to commit", "error", err)
	}
}
