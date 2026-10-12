package audit

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/db"
)

const (
	maxExportDays = 90
	maxExportRows = 100_000
)

// ErrExportLimit means the caller has to narrow the export, not retry it.
var ErrExportLimit = errors.New("export limit")

// Event is one row of the audit log, and its shape in a JSON export.
type Event struct {
	ID          string         `json:"id"`
	Timestamp   time.Time      `json:"timestamp"`
	WorkspaceID string         `json:"workspace_id,omitempty"`
	ActorID     string         `json:"actor_id,omitempty"`
	ActorKind   string         `json:"actor_kind,omitempty"`
	ActorName   string         `json:"actor_name,omitempty"`
	Action      string         `json:"action"`
	Target      string         `json:"target,omitempty"`
	OK          bool           `json:"ok"`
	IP          string         `json:"ip,omitempty"`
	UserAgent   string         `json:"user_agent,omitempty"`
	Details     map[string]any `json:"details,omitempty"`
}

// Append writes the event as nokku_system, tenant transactions cannot write audit rows.
func (s *Service) Append(ctx context.Context, event *Event) error {
	if event == nil {
		return nil
	}
	if event.WorkspaceID == "" {
		return errors.New("audit event without a workspace")
	}
	details, err := json.Marshal(event.Details)
	if err != nil {
		return err
	}
	// marshal(nil) yields "null", the column wants an object.
	if string(details) == "null" {
		details = []byte("{}")
	}
	return s.conn.Sys().InsertAuditLog(ctx, &db.InsertAuditLogParams{
		WorkspaceID: event.WorkspaceID,
		ActorID:     event.ActorID,
		ActorKind:   event.ActorKind,
		ActorName:   event.ActorName,
		Action:      event.Action,
		Target:      event.Target,
		Ok:          event.OK,
		Ip:          event.IP,
		UserAgent:   event.UserAgent,
		Details:     details,
	})
}

func (s *Service) List(ctx context.Context, p *db.ListAuditLogsParams) ([]*Event, int32, error) {
	rows, err := s.conn.Tenant().ListAuditLogs(ctx, p)
	if err != nil {
		return nil, 0, fmt.Errorf("querying events: %w", err)
	}

	events := make([]*Event, 0, len(rows))
	var total int32
	for _, r := range rows {
		total = r.Total
		var details map[string]any
		_ = json.Unmarshal(r.Details, &details)
		events = append(events, &Event{
			ID:          r.ID,
			Timestamp:   r.Timestamp,
			WorkspaceID: r.WorkspaceID,
			ActorID:     r.ActorID,
			ActorKind:   r.ActorKind,
			ActorName:   r.ActorName,
			Action:      r.Action,
			Target:      r.Target,
			OK:          r.Ok,
			IP:          r.Ip,
			UserAgent:   r.UserAgent,
			Details:     details,
		})
	}
	return events, total, nil
}

func (s *Service) Export(
	ctx context.Context,
	p *db.ListAuditLogsParams,
	format nokkuv1.ExportAuditLogsRequest_Format,
) ([]byte, error) {
	if p.StartDate == nil || p.EndDate == nil {
		return nil, fmt.Errorf("%w: start and end date are required", ErrExportLimit)
	}
	if p.EndDate.Sub(*p.StartDate) > maxExportDays*24*time.Hour {
		return nil, fmt.Errorf("%w: the range is longer than %d days", ErrExportLimit, maxExportDays)
	}

	p.Limit, p.Offset = maxExportRows, 0
	events, total, err := s.List(ctx, p)
	if err != nil {
		return nil, err
	}
	if total > maxExportRows {
		return nil, fmt.Errorf(
			"%w: %d events match, at most %d fit, narrow the filters",
			ErrExportLimit,
			total,
			maxExportRows,
		)
	}

	var data []byte
	switch format {
	case nokkuv1.ExportAuditLogsRequest_FORMAT_JSON:
		if data, err = json.Marshal(events); err != nil {
			return nil, err
		}
	case nokkuv1.ExportAuditLogsRequest_FORMAT_CSV:
		if data, err = eventsCSV(events); err != nil {
			return nil, err
		}
	case nokkuv1.ExportAuditLogsRequest_FORMAT_UNSPECIFIED:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func eventsCSV(events []*Event) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{
		"id", "timestamp", "workspace_id",
		"actor_id", "actor_kind", "actor_name",
		"action", "target", "ok",
		"ip", "user_agent", "details",
	})
	for _, e := range events {
		details := "{}"
		if len(e.Details) > 0 {
			if b, err := json.Marshal(e.Details); err == nil {
				details = string(b)
			}
		}
		_ = w.Write([]string{
			e.ID, e.Timestamp.Format(time.RFC3339Nano), e.WorkspaceID,
			e.ActorID, e.ActorKind, e.ActorName,
			e.Action, e.Target, strconv.FormatBool(e.OK),
			e.IP, e.UserAgent, details,
		})
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}
