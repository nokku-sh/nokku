package api

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"connectrpc.com/connect"
	"github.com/mizuchilabs/kata/buildinfo"

	"github.com/nokku-sh/nokku/internal/iam"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
)

type UtilService struct {
	cfg *config.Config
}

func NewUtilService(cfg *config.Config) *UtilService {
	return &UtilService{cfg: cfg}
}

func (s *UtilService) GetVersion(
	_ context.Context,
	_ *nokkuv1.GetVersionRequest,
) (*nokkuv1.GetVersionResponse, error) {
	return &nokkuv1.GetVersionResponse{Version: &buildinfo.Version}, nil
}

func (s *UtilService) Whoami(
	ctx context.Context,
	_ *nokkuv1.WhoamiRequest,
) (*nokkuv1.WhoamiResponse, error) {
	p, ok := iam.PrincipalFromContext(ctx)
	if !ok {
		return nil, NewError(connect.CodeUnauthenticated, "not authenticated")
	}

	out := &nokkuv1.WhoamiResponse{
		Kind:        new(string(p.Kind)),
		SubjectId:   new(p.ID),
		UserId:      new(iam.UserIDFromContext(ctx)),
		WorkspaceId: new(iam.WorkspaceIDFromContext(ctx)),
	}

	switch p.Kind {
	case iam.KindUser, iam.KindCLI, iam.KindWebDevice:
		u, err := s.cfg.IAM.GetUser(ctx)
		if err != nil {
			return nil, DBError(err)
		}
		out.User = u.ToProto()
	case iam.KindServiceAccount:
		if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
			sa, err := q.GetServiceAccount(ctx, p.ID)
			if err != nil {
				return err
			}
			out.ServiceAccount = sa.ToProto()
			return nil
		}); err != nil {
			return nil, DBError(err)
		}
	case iam.KindDaemon:
		if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
			d, err := q.GetDaemon(ctx, p.ID)
			if err != nil {
				return err
			}
			out.Daemon = d.ToProto()
			return nil
		}); err != nil {
			return nil, DBError(err)
		}
	case iam.KindSCIM:
		// SCIM tokens never reach connect.
	}
	return out, nil
}

func (s *UtilService) ListRoles(
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

func (s *UtilService) ListAuditLogs(
	ctx context.Context,
	req *nokkuv1.ListAuditLogsRequest,
) (*nokkuv1.ListAuditLogsResponse, error) {
	params := auditParams(ctx, req.GetWorkspaceId(), req.GetStartDate(), req.GetEndDate())
	params.Limit, params.Offset = req.GetLimit(), req.GetOffset()
	if params.WorkspaceID != nil && len(req.GetActorIds()) > 0 {
		params.ActorIds = req.GetActorIds()
	}
	if len(req.GetActorKinds()) > 0 {
		params.ActorKinds = req.GetActorKinds()
	}
	if len(req.GetActions()) > 0 {
		params.Actions = req.GetActions()
	}
	if req.GetTarget() != "" {
		params.Target = req.Target
	}
	if req.GetSearch() != "" {
		params.Search = req.Search
	}

	events, total, err := s.cfg.Audit.List(ctx, params)
	if err != nil {
		slog.Error("failed to list audit logs", "error", err)
		return nil, ErrInternal
	}
	logs := make([]*nokkuv1.EventLog, 0, len(events))
	for _, e := range events {
		logs = append(logs, e.ToProto())
	}
	return &nokkuv1.ListAuditLogsResponse{Logs: logs, Total: &total}, nil
}

func (s *UtilService) ExportAuditLogs(
	ctx context.Context,
	req *nokkuv1.ExportAuditLogsRequest,
) (*nokkuv1.ExportAuditLogsResponse, error) {
	params := auditParams(ctx, req.GetWorkspaceId(), req.GetStartDate(), req.GetEndDate())
	data, err := s.cfg.Audit.Export(ctx, params, req.GetFormat())
	if err != nil {
		return nil, ErrInternal
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

// auditParams falls back to the caller's own activity without a workspace,
// and to the last 14 days without dates.
func auditParams(
	ctx context.Context,
	workspaceID string,
	start, end *timestamppb.Timestamp,
) *db.ListAuditLogsParams {
	p := &db.ListAuditLogsParams{}
	if workspaceID != "" {
		p.WorkspaceID = &workspaceID
	} else {
		p.ActorIds = []string{iam.SubjectFromContext(ctx)}
	}
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
