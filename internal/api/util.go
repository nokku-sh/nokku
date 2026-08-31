package api

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"github.com/mizuchilabs/kata/buildinfo"

	"github.com/nokku-sh/nokku/internal/iam"

	"github.com/nokku-sh/nokku/internal/audit"
	"github.com/nokku-sh/nokku/internal/billing"
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

// Whoami identifies the authenticated principal: it answers "does my login
// work, and as what" for every credential kind — a browser session, a CLI
// device, a daemon, or a service-account API key. It needs no permission;
// authentication is the check.
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
		u, err := s.cfg.IAM.GetUser(ctx, p.ID)
		if err != nil {
			return nil, DBError(err)
		}
		out.User = db.UserToProto(u)
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
	}
	return out, nil
}

func (s *UtilService) ListRoles(
	_ context.Context,
	_ *nokkuv1.ListRolesRequest,
) (*nokkuv1.ListRolesResponse, error) {
	infos := db.UserFacingRoles()
	roles := make([]*nokkuv1.Role, 0, len(infos))
	for _, r := range infos {
		permissions := make([]string, len(r.Permissions))
		for i, p := range r.Permissions {
			permissions[i] = string(p)
		}
		roles = append(roles, &nokkuv1.Role{
			Name:                        &r.Name,
			Description:                 &r.Description,
			Permissions:                 permissions,
			AssignableToUsers:           &r.AssignableToUsers,
			AssignableToServiceAccounts: &r.AssignableToServiceAccounts,
		})
	}
	return &nokkuv1.ListRolesResponse{Roles: roles}, nil
}

func (s *UtilService) ListAuditLogs(
	ctx context.Context,
	req *nokkuv1.ListAuditLogsRequest,
) (*nokkuv1.ListAuditLogsResponse, error) {
	actor, _ := iam.PrincipalFromContext(ctx)
	var workspaceID string

	if req.GetWorkspaceId() != "" {
		workspaceID = req.GetWorkspaceId()
	} else {
		req.ActorIds = []string{actor.ID}
	}
	if workspaceID == "" && req.ActorIds == nil {
		return nil, NewError(connect.CodeInvalidArgument, "actor is required")
	}

	query := audit.QueryOptions{
		WorkspaceID: workspaceID,
		ActorIDs:    req.GetActorIds(),
		ActorTypes:  req.GetActorTypes(),
		Actions:     req.GetActions(),
		Search:      req.GetSearch(),
		Limit:       req.GetLimit(),
		Offset:      req.GetOffset(),
	}
	if t := req.GetStartDate(); t != nil {
		query.StartDate = t.AsTime()
	}
	if t := req.GetEndDate(); t != nil {
		query.EndDate = t.AsTime()
	}
	// Default to last 14 days if no dates provided
	if req.GetStartDate() == nil && req.GetEndDate() == nil {
		query.EndDate = time.Now()
		query.StartDate = query.EndDate.AddDate(0, 0, -14)
	}

	events, err := s.cfg.Audit.List(ctx, query)
	if err != nil {
		slog.Error("failed to list audit logs", "error", err)
		return nil, ErrInternal
	}

	count, err := s.cfg.Audit.Count(ctx, query)
	if err != nil {
		slog.Error("failed to count audit logs", "error", err)
		return nil, ErrInternal
	}

	return &nokkuv1.ListAuditLogsResponse{
		Logs:  audit.EventsToProto(events),
		Total: &count,
	}, nil
}

func (s *UtilService) ExportAuditLogs(
	ctx context.Context,
	req *nokkuv1.ExportAuditLogsRequest,
) (*nokkuv1.ExportAuditLogsResponse, error) {
	actor, _ := iam.PrincipalFromContext(ctx)
	workspaceID := req.GetWorkspaceId()
	if workspaceID != "" && !s.cfg.Billing.Has(ctx, workspaceID, billing.FeatureAuditExport) {
		return nil, NewError(
			connect.CodeFailedPrecondition,
			"audit export requires an Enterprise plan",
		)
	}

	query := audit.QueryOptions{WorkspaceID: req.GetWorkspaceId()}
	if req.GetStartDate() != nil {
		query.StartDate = req.GetStartDate().AsTime()
	}
	if req.GetEndDate() != nil {
		query.EndDate = req.GetEndDate().AsTime()
	}
	// Default to last 14 days if no dates provided
	if req.GetStartDate() == nil && req.GetEndDate() == nil {
		query.EndDate = time.Now()
		query.StartDate = query.EndDate.AddDate(0, 0, -14)
	}

	if workspaceID == "" {
		query.ActorIDs = []string{actor.ID}
	}

	data, err := s.cfg.Audit.Export(ctx, query, req.GetFormat())
	if err != nil {
		return nil, ErrInternal
	}

	var ext string
	switch req.GetFormat() {
	case nokkuv1.ExportAuditLogsRequest_FORMAT_JSON:
		ext = "json"
	case nokkuv1.ExportAuditLogsRequest_FORMAT_CSV:
		ext = "csv"
	case nokkuv1.ExportAuditLogsRequest_FORMAT_UNSPECIFIED:
		ext = "json"
	}
	filename := fmt.Sprintf("audit-logs-%s.%s.gz", time.Now().Format("2006-01-02"), ext)
	contentType := "application/gzip"

	return &nokkuv1.ExportAuditLogsResponse{
		Data:        data,
		Filename:    &filename,
		ContentType: &contentType,
	}, nil
}
