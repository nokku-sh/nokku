package audit

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
)

type Event struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	WorkspaceID string    `json:"workspace_id"`
	Action      string    `json:"action"`
	ActorID     string    `json:"actor_id"`
	ActorType   string    `json:"actor_type"`
	ActorEmail  string    `json:"actor_email,omitempty"`
	IPAddress   string    `json:"ip_address"`
	UserAgent   string    `json:"user_agent"`
	StatusCode  string    `json:"status_code"`
}

type QueryOptions struct {
	WorkspaceID string
	ActorIDs    []string
	Actions     []string
	StartDate   time.Time
	EndDate     time.Time
	Limit       int32
	Offset      int32
}

type ExportFormat string

const (
	FormatJSON ExportFormat = "json"
	FormatCSV  ExportFormat = "csv"

	MaxExportDays = 90         // Maximum time range for a single export
	MaxExportRows = 10_000_000 // Safety limit
)

func (s *Service) Append(ctx context.Context, event *Event) error {
	var workspaceID, email *string
	if event.WorkspaceID != "" {
		workspaceID = &event.WorkspaceID
	}
	if event.ActorEmail != "" {
		email = &event.ActorEmail
	}

	// Audit writes are server-derived and happen inside arbitrary request
	// flows (including pre-auth and system operations), so they always run
	// as a system transaction.
	return s.conn.WithTx(ctx, func(q *db.Queries) error {
		return q.InsertAuditLog(ctx, &db.InsertAuditLogParams{
			WorkspaceID: workspaceID,
			Action:      event.Action,
			ActorID:     event.ActorID,
			ActorType:   event.ActorType,
			ActorEmail:  email,
			IpAddress:   &event.IPAddress,
			UserAgent:   &event.UserAgent,
			StatusCode:  &event.StatusCode,
		})
	})
}

// query runs fn with a querier appropriate for the requested scope. A
// workspace-scoped read goes through the RLS-constrained, membership-checked
// tenant transaction. A read without a workspace only ever matches
// non-workspace (global) events by query construction, which the tenant role
// may never see, so it runs as a system transaction.
func (s *Service) query(
	ctx context.Context,
	opts QueryOptions,
	fn func(q *db.Queries) error,
) error {
	if opts.WorkspaceID == "" {
		return s.conn.WithTx(ctx, fn)
	}
	return s.conn.WithWorkspace(ctx, fn)
}

func (s *Service) List(
	ctx context.Context,
	opts QueryOptions,
) ([]*Event, error) {
	limit := opts.Limit
	if limit == 0 {
		limit = 10
	}

	var startDate, endDate *time.Time
	if !opts.StartDate.IsZero() {
		startDate = &opts.StartDate
	}
	if !opts.EndDate.IsZero() {
		endDate = &opts.EndDate
	}

	var actorIDs, actions []string
	if len(opts.ActorIDs) > 0 {
		actorIDs = opts.ActorIDs
	}
	if len(opts.Actions) > 0 {
		actions = opts.Actions
	}

	var rows []*db.AuditAuditLog
	if err := s.query(ctx, opts, func(q *db.Queries) (err error) {
		rows, err = q.ListAuditLogs(ctx, &db.ListAuditLogsParams{
			WorkspaceID: opts.WorkspaceID,
			ActorIds:    actorIDs,
			Actions:     actions,
			StartDate:   startDate,
			EndDate:     endDate,
			Limit:       limit,
			Offset:      opts.Offset,
		})
		return err
	}); err != nil {
		return nil, fmt.Errorf("failed to query events: %w", err)
	}

	var events []*Event
	for _, row := range rows {
		workspaceID := ""
		if row.WorkspaceID != nil {
			workspaceID = *row.WorkspaceID
		}

		email := ""
		if row.ActorEmail != nil {
			email = *row.ActorEmail
		}
		ip := ""
		if row.IpAddress != nil {
			ip = *row.IpAddress
		}
		ua := ""
		if row.UserAgent != nil {
			ua = *row.UserAgent
		}
		sc := ""
		if row.StatusCode != nil {
			sc = *row.StatusCode
		}

		events = append(events, &Event{
			ID:          row.ID,
			Timestamp:   row.Timestamp,
			WorkspaceID: workspaceID,
			Action:      row.Action,
			ActorID:     row.ActorID,
			ActorType:   row.ActorType,
			ActorEmail:  email,
			IPAddress:   ip,
			UserAgent:   ua,
			StatusCode:  sc,
		})
	}
	return events, nil
}

func (s *Service) Count(ctx context.Context, opts QueryOptions) (int32, error) {
	var startDate, endDate *time.Time
	if !opts.StartDate.IsZero() {
		startDate = &opts.StartDate
	}
	if !opts.EndDate.IsZero() {
		endDate = &opts.EndDate
	}

	var actorIDs, actions []string
	if len(opts.ActorIDs) > 0 {
		actorIDs = opts.ActorIDs
	}
	if len(opts.Actions) > 0 {
		actions = opts.Actions
	}

	var count int32
	err := s.query(ctx, opts, func(q *db.Queries) (err error) {
		count, err = q.CountAuditLogs(ctx, &db.CountAuditLogsParams{
			WorkspaceID: opts.WorkspaceID,
			ActorIds:    actorIDs,
			Actions:     actions,
			StartDate:   startDate,
			EndDate:     endDate,
		})
		return err
	})
	return count, err
}

func (s *Service) Export(
	ctx context.Context,
	opts QueryOptions,
	format nokkuv1.ExportAuditLogsRequest_Format,
) ([]byte, error) {
	if opts.StartDate.IsZero() || opts.EndDate.IsZero() {
		return nil, fmt.Errorf("start_date and end_date are required for export")
	}

	duration := opts.EndDate.Sub(opts.StartDate)
	if duration > MaxExportDays*24*time.Hour {
		return nil, fmt.Errorf("export time range exceeds maximum of %d days", MaxExportDays)
	}

	count, err := s.Count(ctx, opts)
	if err != nil {
		return nil, err
	}
	if count > MaxExportRows {
		return nil, fmt.Errorf("export contains %d rows, maximum is %d", count, MaxExportRows)
	}

	opts.Limit = count
	events, err := s.List(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to list events: %w", err)
	}

	var data []byte
	switch format {
	case nokkuv1.ExportAuditLogsRequest_FORMAT_JSON:
		data, err = json.Marshal(events)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal JSON: %w", err)
		}

	case nokkuv1.ExportAuditLogsRequest_FORMAT_CSV:
		var buf bytes.Buffer
		w := csv.NewWriter(&buf)

		header := []string{
			"id", "timestamp",
			"actor_id", "actor_type", "actor_email",
			"action", "workspace_id",
			"ip_address", "user_agent", "status_code",
		}
		if err := w.Write(header); err != nil {
			return nil, fmt.Errorf("failed to write CSV header: %w", err)
		}

		for _, event := range events {
			record := []string{
				event.ID,
				event.Timestamp.Format(time.RFC3339Nano),
				event.ActorID,
				event.ActorType,
				event.ActorEmail,
				event.Action,
				event.WorkspaceID,
				event.IPAddress,
				event.UserAgent,
				event.StatusCode,
			}
			if err := w.Write(record); err != nil {
				return nil, fmt.Errorf("failed to write CSV record: %w", err)
			}
		}

		w.Flush()
		if err := w.Error(); err != nil {
			return nil, fmt.Errorf("failed to flush CSV: %w", err)
		}
		data = buf.Bytes()

	case nokkuv1.ExportAuditLogsRequest_FORMAT_UNSPECIFIED:
		return nil, fmt.Errorf("unsupported export format: %s", format)

	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}

	var compressed bytes.Buffer
	gzWriter := gzip.NewWriter(&compressed)
	if _, err := gzWriter.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write gzip: %w", err)
	}
	if err := gzWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to close gzip: %w", err)
	}

	return compressed.Bytes(), nil
}
