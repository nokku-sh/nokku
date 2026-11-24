package api

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"connectrpc.com/connect/v2"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/app"
	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/db"
)

var auditOutcomes = map[nokkuv1.AuditOutcome]string{
	nokkuv1.AuditOutcome_AUDIT_OUTCOME_UNSPECIFIED: "",
	nokkuv1.AuditOutcome_AUDIT_OUTCOME_SUCCEEDED:   "succeeded",
	nokkuv1.AuditOutcome_AUDIT_OUTCOME_FAILED:      "failed",
	nokkuv1.AuditOutcome_AUDIT_OUTCOME_DENIED:      "denied",
}

type auditLogService struct {
	cfg *app.Config
}

func (s *auditLogService) ListAuditLogs(
	ctx context.Context,
	req *nokkuv1.ListAuditLogsRequest,
) (*nokkuv1.ListAuditLogsResponse, error) {
	params := auditParams(req.GetFilter())
	params.Limit, params.Offset = req.GetLimit(), req.GetOffset()

	events, total, err := s.cfg.Audit.List(ctx, params)
	if err != nil {
		return nil, err
	}
	days := s.cfg.Entitlements.Resolve(ctx, actor.WorkspaceIDFromContext(ctx)).AuditRetentionDays
	retention := int32(min(days, math.MaxInt32)) //nolint:gosec // clamped to int32 just before
	return &nokkuv1.ListAuditLogsResponse{Events: eventLogs(events), Total: &total, RetentionDays: &retention}, nil
}

func (s *auditLogService) PollAuditLogs(
	ctx context.Context,
	req *nokkuv1.PollAuditLogsRequest,
) (*nokkuv1.PollAuditLogsResponse, error) {
	events, cursor, err := s.cfg.Audit.Poll(ctx, req.GetCursor(), req.GetLimit())
	if errors.Is(err, audit.ErrCursor) {
		return nil, connect.NewError(connect.CodeInvalidArgument, err.Error())
	}
	if err != nil {
		return nil, err
	}
	return &nokkuv1.PollAuditLogsResponse{Events: eventLogs(events), Cursor: &cursor}, nil
}

func (s *auditLogService) ListMyActivity(
	ctx context.Context,
	req *nokkuv1.ListMyActivityRequest,
) (*nokkuv1.ListMyActivityResponse, error) {
	f := req.GetFilter()
	params := auditParams(f)
	// Your own events have an index of their own, so they go back as far as the log keeps them.
	if f.GetStartDate() == nil && f.GetEndDate() == nil {
		params.StartDate, params.EndDate = nil, nil
	}
	// After the filter, so it can't widen to someone else's events.
	params.ActorIds = []string{actor.SubjectFromContext(ctx)}
	params.Limit, params.Offset = req.GetLimit(), req.GetOffset()
	events, total, err := s.cfg.Audit.List(ctx, params)
	if err != nil {
		return nil, err
	}
	return &nokkuv1.ListMyActivityResponse{Events: eventLogs(events), Total: &total}, nil
}

func (s *auditLogService) ExportAuditLogs(
	ctx context.Context,
	req *nokkuv1.ExportAuditLogsRequest,
) (*nokkuv1.ExportAuditLogsResponse, error) {
	params := auditParams(req.GetFilter())
	data, err := s.cfg.Audit.Export(ctx, params, req.GetFormat())
	if errors.Is(err, audit.ErrExportLimit) {
		return nil, connect.NewError(connect.CodeFailedPrecondition, err.Error())
	}
	if err != nil {
		return nil, err
	}

	ext := "json"
	if req.GetFormat() == nokkuv1.ExportAuditLogsRequest_FORMAT_CSV {
		ext = "csv"
	}
	return &nokkuv1.ExportAuditLogsResponse{
		Data:        data,
		Filename:    new(fmt.Sprintf("audit-logs-%s.%s.gz", time.Now().Format(time.DateOnly), ext)),
		ContentType: new("application/gzip"),
	}, nil
}

func eventLogs(events []*audit.Event) []*nokkuv1.AuditEvent {
	logs := make([]*nokkuv1.AuditEvent, 0, len(events))
	for _, e := range events {
		logs = append(logs, e.ToProto())
	}
	return logs
}

// auditParams defaults to 14 days. The audit service fills in the workspace.
func auditParams(f *nokkuv1.AuditLogFilter) *db.ListAuditLogsParams {
	p := &db.ListAuditLogsParams{}
	if len(f.GetActorIds()) > 0 {
		p.ActorIds = f.GetActorIds()
	}
	for _, kind := range f.GetActorKinds() {
		p.ActorKinds = append(p.ActorKinds, audit.ActorKindName(kind))
	}
	if len(f.GetActions()) > 0 {
		p.Actions = f.GetActions()
	}
	if len(f.GetExcludedActions()) > 0 {
		p.ExcludedActions = f.GetExcludedActions()
	}
	if f.GetTarget() != "" {
		p.Target = new(f.GetTarget())
	}
	if f.GetSearch() != "" {
		p.Search = new(f.GetSearch())
	}
	if outcome := auditOutcomes[f.GetOutcome()]; outcome != "" {
		p.Outcome = &outcome
	}

	start, end := f.GetStartDate(), f.GetEndDate()
	if start == nil && end == nil {
		now := time.Now()
		p.StartDate, p.EndDate = new(now.AddDate(0, 0, -14)), &now
	}
	if start != nil {
		p.StartDate = new(start.AsTime())
	}
	if end != nil {
		p.EndDate = new(end.AsTime())
	}
	return p
}
