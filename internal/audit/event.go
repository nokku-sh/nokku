package audit

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
)

type Event struct {
	ID          string         `json:"id"`
	Timestamp   time.Time      `json:"timestamp"`
	WorkspaceID string         `json:"workspace_id"`
	Action      string         `json:"action"`
	ActorID     string         `json:"actor_id"`
	ActorType   string         `json:"actor_type"`
	ActorEmail  string         `json:"actor_email,omitempty"`
	IPAddress   string         `json:"ip_address"`
	UserAgent   string         `json:"user_agent"`
	StatusCode  string         `json:"status_code"`
	Details     map[string]any `json:"details,omitempty"`
}

type QueryOptions struct {
	WorkspaceID string
	ActorIDs    []string
	ActorTypes  []string
	Actions     []string
	Search      string
	StartDate   time.Time
	EndDate     time.Time
	Limit       int32
	Offset      int32
}

const (
	MaxExportDays = 90         // Maximum time range for a single export
	MaxExportRows = 10_000_000 // Safety limit
)

// Append fans an event out to every configured sink. A failing sink is
// reported but never fatal: the caller is usually on a request path, and an
// audit write must not take that down.
func (s *Service) Append(ctx context.Context, event *Event) error {
	if event == nil {
		return nil
	}

	var errs []error
	for _, sink := range s.sinks {
		if err := sink.Append(ctx, event); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// query runs fn with a querier appropriate for the requested scope, always
// under RLS. A workspace-scoped read is pinned to that tenant (and the
// caller's membership is checked) via WithWorkspace. A read without a
// workspace is a principal-scoped read of global events, pinned to the single
// requested actor via WithActor.
func (s *Service) query(
	ctx context.Context,
	opts QueryOptions,
	fn func(q *db.Queries) error,
) error {
	if opts.WorkspaceID != "" {
		return s.conn.WithWorkspace(ctx, fn)
	}
	if len(opts.ActorIDs) != 1 || opts.ActorIDs[0] == "" {
		return fmt.Errorf("global audit read requires exactly one actor_id")
	}
	return s.conn.WithActor(ctx, opts.ActorIDs[0], fn)
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

	var actorIDs, actions, actorTypes []string
	if len(opts.ActorIDs) > 0 {
		actorIDs = opts.ActorIDs
	}
	if len(opts.Actions) > 0 {
		actions = opts.Actions
	}
	if len(opts.ActorTypes) > 0 {
		actorTypes = opts.ActorTypes
	}

	var rows []*db.AuditAuditLog
	if err := s.query(ctx, opts, func(q *db.Queries) (err error) {
		rows, err = q.ListAuditLogs(ctx, &db.ListAuditLogsParams{
			WorkspaceID: opts.WorkspaceID,
			ActorIds:    actorIDs,
			ActorTypes:  actorTypes,
			Actions:     actions,
			Search:      new(opts.Search),
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

		actorID := ""
		if row.ActorID != nil {
			actorID = *row.ActorID
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

		var details map[string]any
		if len(row.Details) > 0 {
			_ = json.Unmarshal(row.Details, &details)
		}

		events = append(events, &Event{
			ID:          row.ID,
			Timestamp:   row.Timestamp,
			WorkspaceID: workspaceID,
			Action:      row.Action,
			ActorID:     actorID,
			ActorType:   row.ActorType,
			ActorEmail:  email,
			IPAddress:   ip,
			UserAgent:   ua,
			StatusCode:  sc,
			Details:     details,
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

	var actorIDs, actions, actorTypes []string
	if len(opts.ActorIDs) > 0 {
		actorIDs = opts.ActorIDs
	}
	if len(opts.Actions) > 0 {
		actions = opts.Actions
	}
	if len(opts.ActorTypes) > 0 {
		actorTypes = opts.ActorTypes
	}

	var count int32
	err := s.query(ctx, opts, func(q *db.Queries) (err error) {
		count, err = q.CountAuditLogs(ctx, &db.CountAuditLogsParams{
			WorkspaceID: opts.WorkspaceID,
			ActorIds:    actorIDs,
			ActorTypes:  actorTypes,
			Actions:     actions,
			Search:      new(opts.Search),
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
			"ip_address", "user_agent", "status_code", "details",
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
				detailsJSON(event.Details),
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
		// Listed separately because the exhaustive linter requires every enum
		// value, even though it lands on the same rejection as default.
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

// detailsJSON renders the details map as a JSON string for CSV output. A nil
// or empty map becomes an empty JSON object so the cell is never ambiguous.
func detailsJSON(details map[string]any) string {
	if len(details) == 0 {
		return "{}"
	}
	b, err := json.Marshal(details)
	if err != nil {
		return "{}"
	}
	return string(b)
}
