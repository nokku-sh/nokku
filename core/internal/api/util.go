package api

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/mizuchilabs/kata/buildinfo"
	"google.golang.org/protobuf/types/known/durationpb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/access"
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

type utilService struct {
	cfg *app.Config
}

func (s *utilService) GetVersion(
	_ context.Context,
	_ *nokkuv1.GetVersionRequest,
) (*nokkuv1.GetVersionResponse, error) {
	return &nokkuv1.GetVersionResponse{Version: &buildinfo.Version}, nil
}

func (s *utilService) GetInstanceInfo(
	ctx context.Context,
	_ *nokkuv1.GetInstanceInfoRequest,
) (*nokkuv1.GetInstanceInfoResponse, error) {
	op := s.cfg.Email.Operator
	signup := s.cfg.SaaS && actor.WorkspaceIDFromContext(ctx) == ""
	info := &nokkuv1.GetInstanceInfoResponse{
		OperatorName: &op.Name,
		SupportEmail: &op.SupportEmail,
		WebsiteUrl:   &op.WebsiteURL,
		TermsUrl:     &op.TermsURL,
		PrivacyUrl:   &op.PrivacyURL,
		ImprintUrl:   &op.ImprintURL,
		Hosted:       new(s.cfg.SaaS),
		Signup:       &signup,
	}
	if signup {
		info.WorkspaceDomain = new(s.cfg.Tenant.Domain())
	}
	return info, nil
}

func (s *utilService) ListRoles(
	_ context.Context,
	_ *nokkuv1.ListRolesRequest,
) (*nokkuv1.ListRolesResponse, error) {
	// Every role one can hand out. Ownership only moves through a transfer.
	var roles []*nokkuv1.Role
	for r := nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER; r < nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER; r++ {
		roles = append(roles, &nokkuv1.Role{Role: new(r), Description: new(db.RoleDescription(r))})
	}
	return &nokkuv1.ListRolesResponse{Roles: roles}, nil
}

func (s *utilService) ListAuditLogs(
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
	return &nokkuv1.ListAuditLogsResponse{Logs: eventLogs(events), Total: &total, RetentionDays: &retention}, nil
}

func (s *utilService) PollAuditLogs(
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
	return &nokkuv1.PollAuditLogsResponse{Logs: eventLogs(events), Cursor: &cursor}, nil
}

func (s *utilService) ListMyActivity(
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
	return &nokkuv1.ListMyActivityResponse{Logs: eventLogs(events), Total: &total}, nil
}

func (s *utilService) ExportAuditLogs(
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

func (s *utilService) ExportAccessReport(
	ctx context.Context,
	req *nokkuv1.ExportAccessReportRequest,
) (*nokkuv1.ExportAccessReportResponse, error) {
	rows, err := s.cfg.Conn.Tenant().ListAccessReport(ctx)
	if err != nil {
		return nil, err
	}
	data, err := access.Report(rows, req.GetFormat())
	if err != nil {
		return nil, err
	}

	ext, contentType := "json", "application/json"
	if req.GetFormat() == nokkuv1.ExportAuditLogsRequest_FORMAT_CSV {
		ext, contentType = "csv", "text/csv"
	}
	return &nokkuv1.ExportAccessReportResponse{
		Data:        data,
		Filename:    new(fmt.Sprintf("access-report-%s.%s", time.Now().Format(time.DateOnly), ext)),
		ContentType: new(contentType),
	}, nil
}

func eventLogs(events []*audit.Event) []*nokkuv1.EventLog {
	logs := make([]*nokkuv1.EventLog, 0, len(events))
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
	if len(f.GetActorKinds()) > 0 {
		p.ActorKinds = f.GetActorKinds()
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

func optDuration(d *durationpb.Duration) *time.Duration {
	if d == nil {
		return nil
	}
	return new(d.AsDuration())
}

// auditName runs before the change, so a delete keeps the name of what it removed.
func auditName(ctx context.Context, q *db.Queries, key, id string) error {
	names, err := q.GetNames(ctx, []string{id})
	if err != nil {
		return err
	}
	audit.Set(ctx, key, names[0])
	return nil
}
