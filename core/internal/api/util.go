package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	"connectrpc.com/connect"
	"github.com/mizuchilabs/kata/buildinfo"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/audit"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
)

type utilService struct {
	cfg *config.Config
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
	saas := s.cfg.SaaS
	meta, _ := actor.RequestMetaFromContext(ctx)
	return &nokkuv1.GetInstanceInfoResponse{
		OperatorName: &op.Name,
		SupportEmail: &op.SupportEmail,
		WebsiteUrl:   &op.WebsiteURL,
		TermsUrl:     &op.TermsURL,
		PrivacyUrl:   &op.PrivacyURL,
		ImprintUrl:   &op.ImprintURL,
		Mode:         new(s.cfg.Mode()),
		Signup:       new(saas && actor.WorkspaceIDFromContext(ctx) == ""),
		CaPin:        new(s.cfg.WebPKI.Pin(meta)),
	}, nil
}

func (s *utilService) Whoami(
	ctx context.Context,
	_ *nokkuv1.WhoamiRequest,
) (*nokkuv1.WhoamiResponse, error) {
	p, ok := actor.PrincipalFromContext(ctx)
	if !ok {
		return nil, newError(connect.CodeUnauthenticated, "not authenticated")
	}

	out := &nokkuv1.WhoamiResponse{
		Kind:      new(string(p.Kind)),
		SubjectId: new(p.ID),
	}

	switch p.Kind {
	case actor.KindUser, actor.KindCLI:
		u, err := s.cfg.IAM.GetUser(ctx)
		if err != nil {
			return nil, err
		}
		out.User = u.ToProto()
	case actor.KindServiceAccount:
		sa, err := s.cfg.Conn.Tenant().GetServiceAccount(ctx, p.ID)
		if err != nil {
			return nil, err
		}
		out.ServiceAccount = sa.ToProto()
	case actor.KindDaemon:
		d, err := s.cfg.Conn.Tenant().GetDaemon(ctx, p.ID)
		if err != nil {
			return nil, err
		}
		out.Daemon = d.ToProto()
	case actor.KindSCIM:
		// SCIM tokens never reach connect.
	}
	return out, nil
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
		slog.Error("failed to list audit logs", "error", err)
		return nil, errInternal
	}
	days := s.cfg.Entitlements.Resolve(ctx, actor.WorkspaceIDFromContext(ctx)).AuditRetentionDays
	retention := int32(min(days, math.MaxInt32)) //nolint:gosec // clamped to int32 just before
	return &nokkuv1.ListAuditLogsResponse{Logs: eventLogs(events), Total: &total, RetentionDays: &retention}, nil
}

func (s *utilService) ListMyActivity(
	ctx context.Context,
	req *nokkuv1.ListMyActivityRequest,
) (*nokkuv1.ListMyActivityResponse, error) {
	params := auditParams(nil)
	params.ActorIds = []string{actor.SubjectFromContext(ctx)}
	params.Limit, params.Offset = req.GetLimit(), req.GetOffset()
	events, total, err := s.cfg.Audit.List(ctx, params)
	if err != nil {
		slog.Error("failed to list activity", "error", err)
		return nil, errInternal
	}
	return &nokkuv1.ListMyActivityResponse{Logs: eventLogs(events), Total: &total}, nil
}

func eventLogs(events []*audit.Event) []*nokkuv1.EventLog {
	logs := make([]*nokkuv1.EventLog, 0, len(events))
	for _, e := range events {
		logs = append(logs, e.ToProto())
	}
	return logs
}

func (s *utilService) ExportAuditLogs(
	ctx context.Context,
	req *nokkuv1.ExportAuditLogsRequest,
) (*nokkuv1.ExportAuditLogsResponse, error) {
	params := auditParams(req.GetFilter())
	data, err := s.cfg.Audit.Export(ctx, params, req.GetFormat())
	if errors.Is(err, audit.ErrExportLimit) {
		return nil, newError(connect.CodeFailedPrecondition, err.Error())
	}
	if err != nil {
		slog.Error("failed to export audit logs", "error", err)
		return nil, errInternal
	}

	ext := "json"
	if req.GetFormat() == nokkuv1.ExportAuditLogsRequest_FORMAT_CSV {
		ext = "csv"
	}
	return &nokkuv1.ExportAuditLogsResponse{
		Data:        data,
		Filename:    new(fmt.Sprintf("audit-logs-%s.%s.gz", time.Now().Format("2006-01-02"), ext)),
		ContentType: new("application/gzip"),
	}, nil
}

var auditOutcomes = map[nokkuv1.AuditOutcome]string{
	nokkuv1.AuditOutcome_AUDIT_OUTCOME_UNSPECIFIED: "",
	nokkuv1.AuditOutcome_AUDIT_OUTCOME_SUCCEEDED:   "succeeded",
	nokkuv1.AuditOutcome_AUDIT_OUTCOME_FAILED:      "failed",
	nokkuv1.AuditOutcome_AUDIT_OUTCOME_DENIED:      "denied",
}

// auditParams falls back to the last 14 days without dates. The audit service fills in the workspace.
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
