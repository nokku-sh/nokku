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
	maxRetentionDays = 365
)

type Service struct {
	conn         *db.Connection
	entitlements *entitlement.Service
	// sinks receive every event. See Sink.
	sinks []Sink
}

func New(
	ctx context.Context,
	conn *db.Connection,
	entitlements *entitlement.Service,
) (*Service, error) {
	s := &Service{
		conn:         conn,
		entitlements: entitlements,
		sinks: []Sink{
			NewPostgresSink(conn),
			NewWebhookSink(ctx, conn, entitlements),
		},
	}

	if err := s.setupPartitions(ctx); err != nil {
		return nil, err
	}

	go s.runBackgroundJobs(ctx)
	return s, nil
}

func (s *Service) setupPartitions(ctx context.Context) error {
	now := time.Now().UTC() // use UTC

	// Normalize to the 1st of the current month to prevent AddDate wraparound issues
	currentMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)

	// Partition management is DDL and requires the table owner.
	tx, err := s.conn.AdminPool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Acquire the transaction-level advisory lock so only one instance
	// manages partitions.
	var locked bool
	err = tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtext('audit-partitions'))`).
		Scan(&locked)
	if err != nil {
		return fmt.Errorf("failed to query advisory lock: %w", err)
	}
	if !locked {
		slog.Debug("partition management skipped, another instance running")
		return nil
	}

	if err := s.createPartitionForMonth(ctx, tx, currentMonth); err != nil {
		return err
	}

	// A server upgraded (or booted) while the local calendar is ahead of UTC
	// can still receive rows stamped with the previous UTC month; keep that
	// partition around so those inserts never hit a missing partition.
	if err := s.createPartitionForMonth(ctx, tx, currentMonth.AddDate(0, -1, 0)); err != nil {
		return err
	}

	nextMonth := currentMonth.AddDate(0, 1, 0)
	if err := s.createPartitionForMonth(ctx, tx, nextMonth); err != nil {
		return err
	}

	// Keep enough partitions for the Enterprise 365-day retention policy,
	// including the current partial month and a safety margin.
	retentionFloor := currentMonth.AddDate(0, -14, 0)
	if err := s.dropPartitionsBefore(ctx, tx, retentionFloor); err != nil {
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
		slog.Error("failed to create partition", "table", tableName, "error", err)
		return err
	}
	return nil
}

func (s *Service) dropPartitionsBefore(ctx context.Context, tx pgx.Tx, t time.Time) error {
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

		// Remove double quotes injected by Postgres regclass.
		shortName = strings.Trim(shortName, "\"")

		// Partition names are zero-padded, so string comparison works:
		// y2025m01 < y2025m10.
		if shortName < thresholdName {
			dropQuery := `DROP TABLE IF EXISTS ` + partitionName + `;`

			if _, err := tx.Exec(ctx, dropQuery); err != nil {
				slog.Error("failed to drop partition", "table", partitionName, "error", err)
				return err
			}
		}
	}
	return nil
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

	// Retention deletes across every workspace: system transaction (BYPASSRLS).
	tx, err := s.conn.AdminPool.Begin(ctx)
	if err != nil {
		slog.Error("audit retention failed to begin transaction", "error", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// The audit table refuses DELETE unless the transaction opts in here,
	// which leaves retention its one legitimate path to erasing rows.
	if _, err := tx.Exec(ctx, `SET LOCAL nokku.audit_retention = 'on'`); err != nil {
		slog.Error("audit retention failed to enable the delete guard", "error", err)
		return
	}

	var locked bool
	err = tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtext('audit-retention'))`).
		Scan(&locked)
	if err != nil {
		slog.Error("audit retention failed to acquire lock", "error", err)
		return
	}
	if !locked {
		slog.Debug("audit retention skipped, another instance running")
		return
	}

	q := db.New(tx)

	// per-workspace audit log cleanup

	workspaceIDs, err := q.ListWorkspaceAuditLogWorkspaceIDs(ctx)
	if err != nil {
		slog.Error("audit retention failed to list workspaces", "error", err)
		return
	}

	for _, wsID := range workspaceIDs {
		if wsID == nil {
			continue
		}
		retentionDays := s.entitlements.RetentionDays(ctx, *wsID)
		hardcap := int64(maxRetentionDays)

		if retentionDays > hardcap {
			retentionDays = hardcap
		}

		cutoff := now.AddDate(0, 0, -int(retentionDays))

		deleted, err := q.DeleteWorkspaceAuditLogs(ctx, &db.DeleteWorkspaceAuditLogsParams{
			WorkspaceID: wsID,
			Cutoff:      cutoff,
		})
		if err != nil {
			slog.Error("audit retention failed to delete logs",
				"workspace_id", wsID, "error", err)
			continue
		}
		if deleted > 0 {
			slog.Debug("audit retention cleaned logs",
				"workspace_id", wsID, "deleted", deleted,
				"retention_days", retentionDays)
		}
	}

	// Orphan (non-workspace) audit log cleanup

	orphanCutoff := now.AddDate(0, 0, -maxRetentionDays)
	deleted, err := q.DeleteOrphanAuditLogs(ctx, orphanCutoff)
	if err != nil {
		slog.Error("audit retention failed to delete orphan logs", "error", err)
		return
	}
	if deleted > 0 {
		slog.Debug("audit retention cleaned orphan logs", "deleted", deleted)
	}

	if err := tx.Commit(ctx); err != nil {
		slog.Error("audit retention failed to commit", "error", err)
	}
}
