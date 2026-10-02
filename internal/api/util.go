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

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/audit"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
)

type utilService struct {
	cfg *config.Config
}

func newUtilService(cfg *config.Config) *utilService {
	return &utilService{cfg: cfg}
}

func (s *utilService) GetVersion(
	_ context.Context,
	_ *nokkuv1.GetVersionRequest,
) (*nokkuv1.GetVersionResponse, error) {
	return &nokkuv1.GetVersionResponse{Version: &buildinfo.Version}, nil
}

func (s *utilService) GetInstanceInfo(
	_ context.Context,
	_ *nokkuv1.GetInstanceInfoRequest,
) (*nokkuv1.GetInstanceInfoResponse, error) {
	op := s.cfg.Email.Operator
	return &nokkuv1.GetInstanceInfoResponse{
		OperatorName: &op.Name,
		SupportEmail: &op.SupportEmail,
		WebsiteUrl:   &op.WebsiteURL,
		TermsUrl:     &op.TermsURL,
		PrivacyUrl:   &op.PrivacyURL,
		ImprintUrl:   &op.ImprintURL,
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
		Kind:        new(string(p.Kind)),
		SubjectId:   new(p.ID),
		UserId:      new(actor.UserIDFromContext(ctx)),
		WorkspaceId: new(actor.WorkspaceIDFromContext(ctx)),
	}

	switch p.Kind {
	case actor.KindUser, actor.KindCLI, actor.KindWebDevice:
		u, err := s.cfg.IAM.GetUser(ctx)
		if err != nil {
			return nil, err
		}
		out.User = u.ToProto()
	case actor.KindServiceAccount:
		if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
			sa, err := q.GetServiceAccount(ctx, p.ID)
			if err != nil {
				return err
			}
			out.ServiceAccount = sa.ToProto()
			return nil
		}); err != nil {
			return nil, err
		}
	case actor.KindDaemon:
		if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
			d, err := q.GetDaemon(ctx, p.ID)
			if err != nil {
				return err
			}
			out.Daemon = d.ToProto()
			return nil
		}); err != nil {
			return nil, err
		}
	case actor.KindSCIM:
		// SCIM tokens never reach connect.
	}
	return out, nil
}

func (s *utilService) ListRoles(
	_ context.Context,
	_ *nokkuv1.ListRolesRequest,
) (*nokkuv1.ListRolesResponse, error) {
	roles := make([]*nokkuv1.Role, 0, len(db.Roles))
	for _, r := range db.Roles {
		if r == db.RoleOwner {
			continue
		}
		roles = append(roles, &nokkuv1.Role{Name: new(string(r)), Description: new(r.Description())})
	}
	return &nokkuv1.ListRolesResponse{Roles: roles}, nil
}

func (s *utilService) ListAuditLogs(
	ctx context.Context,
	req *nokkuv1.ListAuditLogsRequest,
) (*nokkuv1.ListAuditLogsResponse, error) {
	params := auditParams(ctx, req.GetWorkspaceId(), req.GetFilter())
	params.Limit, params.Offset = req.GetLimit(), req.GetOffset()

	events, total, err := s.cfg.Audit.List(ctx, params)
	if err != nil {
		slog.Error("failed to list audit logs", "error", err)
		return nil, errInternal
	}
	logs := make([]*nokkuv1.EventLog, 0, len(events))
	for _, e := range events {
		logs = append(logs, e.ToProto())
	}
	var retention int32
	if params.WorkspaceID != nil {
		days := s.cfg.Entitlements.Resolve(ctx, *params.WorkspaceID).RetentionDays
		retention = int32(min(days, math.MaxInt32)) //nolint:gosec // clamped to int32 just before
	}
	return &nokkuv1.ListAuditLogsResponse{Logs: logs, Total: &total, RetentionDays: &retention}, nil
}

func (s *utilService) ExportAuditLogs(
	ctx context.Context,
	req *nokkuv1.ExportAuditLogsRequest,
) (*nokkuv1.ExportAuditLogsResponse, error) {
	params := auditParams(ctx, req.GetWorkspaceId(), req.GetFilter())
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

// auditParams falls back to the caller's own activity without a workspace,
// and to the last 14 days without dates. Other actors only filter a
// workspace log, the personal log is always the caller's.
func auditParams(ctx context.Context, workspaceID string, f *nokkuv1.AuditLogFilter) *db.ListAuditLogsParams {
	p := &db.ListAuditLogsParams{}
	if workspaceID != "" {
		p.WorkspaceID = &workspaceID
		if len(f.GetActorIds()) > 0 {
			p.ActorIds = f.GetActorIds()
		}
	} else {
		p.ActorIds = []string{actor.SubjectFromContext(ctx)}
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
