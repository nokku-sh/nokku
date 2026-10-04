package api

import (
	"context"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/audit"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/ssh"
)

func defaultWorkspaceSettings() *nokkuv1.WorkspaceSettings {
	return &nokkuv1.WorkspaceSettings{
		DefaultDaemonConfig: &nokkuv1.DaemonConfig{
			RecordSessions:       new(true),
			AllowForwarding:      new(true),
			AllowAgentForwarding: new(true),
			GatewayPorts:         new(false),
		},
	}
}

type workspaceService struct {
	cfg *config.Config
}

func newWorkspaceService(cfg *config.Config) *workspaceService {
	return &workspaceService{cfg: cfg}
}

func (s *workspaceService) GetWorkspace(
	ctx context.Context,
	req *nokkuv1.GetWorkspaceRequest,
) (*nokkuv1.GetWorkspaceResponse, error) {
	var workspace *db.Workspace
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		workspace, err = q.GetWorkspace(ctx, req.GetWorkspaceId())
		return err
	}); err != nil {
		return nil, err
	}
	role, err := s.cfg.Conn.Sys().GetActorRole(ctx, &db.GetActorRoleParams{
		WorkspaceID: workspace.ID,
		ActorID:     actor.SubjectFromContext(ctx),
	})
	if err != nil {
		return nil, err
	}
	result := workspace.ToProto()
	result.Role = &role
	// The webhook secret signs events to the customer's SIEM, only the
	// roles that manage it read it back.
	if settings := result.GetSettings(); settings != nil && !db.Role(role).AtLeast(db.RoleAdmin) {
		settings.AuditWebhookUrl, settings.AuditWebhookSecret = nil, nil
	}
	return &nokkuv1.GetWorkspaceResponse{Workspace: result}, nil
}

func (s *workspaceService) CreateWorkspace(
	ctx context.Context,
	req *nokkuv1.CreateWorkspaceRequest,
) (*nokkuv1.CreateWorkspaceResponse, error) {
	user, err := s.cfg.IAM.GetUser(ctx)
	if err != nil {
		return nil, err
	}

	var count int32
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		count, err = q.CountWorkspacesByOwner(ctx, user.ID)
		return err
	}); err != nil {
		return nil, err
	}
	if count >= 5 {
		return nil, newError(connect.CodeResourceExhausted, "maximum number of workspaces reached")
	}

	workspace, err := s.initializeWorkspace(ctx, &db.CreateWorkspaceParams{
		Name:        req.GetName(),
		Description: req.Description,
		CreatedBy:   user.ID,
		Settings:    defaultWorkspaceSettings(),
	})
	if err != nil {
		return nil, err
	}
	audit.SetTarget(ctx, workspace.GetId())

	return &nokkuv1.CreateWorkspaceResponse{
		Workspace: workspace,
	}, nil
}

func (s *workspaceService) UpdateWorkspace(
	ctx context.Context,
	req *nokkuv1.UpdateWorkspaceRequest,
) (*nokkuv1.UpdateWorkspaceResponse, error) {
	var workspace *db.Workspace
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		base, err := q.GetWorkspace(ctx, req.GetWorkspaceId())
		if err != nil {
			return err
		}

		proto.Merge(base.Settings, req.GetSettings())
		workspace, err = q.UpdateWorkspace(ctx, &db.UpdateWorkspaceParams{
			WorkspaceID: req.GetWorkspaceId(),
			Name:        req.Name,
			Description: req.Description,
			Settings:    base.Settings,
		})
		return err
	}); err != nil {
		return nil, err
	}

	return &nokkuv1.UpdateWorkspaceResponse{
		Workspace: workspace.ToProto(),
	}, nil
}

func (s *workspaceService) DeleteWorkspace(
	ctx context.Context,
	req *nokkuv1.DeleteWorkspaceRequest,
) (*nokkuv1.DeleteWorkspaceResponse, error) {
	if s.cfg.Billing.Enabled() {
		if err := s.cfg.Billing.Cancel(ctx, req.GetWorkspaceId(), true, ""); err != nil {
			return nil, errInternal
		}
	}

	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		return q.DeleteWorkspace(ctx, req.GetWorkspaceId())
	}); err != nil {
		return nil, err
	}
	s.cfg.Record.PurgeWorkspace(ctx, req.GetWorkspaceId())
	return &nokkuv1.DeleteWorkspaceResponse{}, nil
}

func (s *workspaceService) ListWorkspaces(
	ctx context.Context,
	_ *nokkuv1.ListWorkspacesRequest,
) (*nokkuv1.ListWorkspacesResponse, error) {
	var workspaces []*db.Workspace
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		workspaces, err = q.ListWorkspaces(ctx)
		return err
	}); err != nil {
		return nil, err
	}
	roles, err := s.cfg.Conn.Sys().ListActorRoles(ctx, actor.SubjectFromContext(ctx))
	if err != nil {
		return nil, err
	}

	roleByWorkspace := make(map[string]string, len(roles))
	for _, r := range roles {
		roleByWorkspace[r.WorkspaceID] = r.RoleName
	}
	result := db.WorkspacesToProto(workspaces)
	for _, w := range result {
		if role, ok := roleByWorkspace[w.GetId()]; ok {
			w.Role = &role
		}
		if settings := w.GetSettings(); settings != nil && !db.Role(w.GetRole()).AtLeast(db.RoleAdmin) {
			settings.AuditWebhookUrl, settings.AuditWebhookSecret = nil, nil
		}
	}
	return &nokkuv1.ListWorkspacesResponse{Workspaces: result}, nil
}

func (s *workspaceService) GetWorkspaceMember(
	ctx context.Context,
	req *nokkuv1.GetWorkspaceMemberRequest,
) (*nokkuv1.GetWorkspaceMemberResponse, error) {
	if req.GetWorkspaceId() == "" {
		return nil, errInvalidInput
	}

	var m *db.GetWorkspaceMemberRow
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		m, err = q.GetWorkspaceMember(ctx, &db.GetWorkspaceMemberParams{
			WorkspaceID: req.GetWorkspaceId(),
			UserID:      req.GetUserId(),
		})
		return err
	}); err != nil {
		return nil, err
	}
	return &nokkuv1.GetWorkspaceMemberResponse{
		Member: &nokkuv1.WorkspaceMember{
			Id:            &m.UserID,
			WorkspaceId:   &m.WorkspaceID,
			Name:          &m.Name,
			Email:         &m.Email,
			EmailVerified: &m.EmailVerified,
			Picture:       m.Picture,
			RoleName:      &m.RoleName,
			CreatedAt:     db.SafeTimestamp(&m.CreatedAt),
			UpdatedAt:     db.SafeTimestamp(&m.UpdatedAt),
		},
	}, nil
}

func (s *workspaceService) UpdateWorkspaceMember(
	ctx context.Context,
	req *nokkuv1.UpdateWorkspaceMemberRequest,
) (*nokkuv1.UpdateWorkspaceMemberResponse, error) {
	// Ownership moves only through UpdateWorkspaceOwner.
	if !callerRole(ctx).CanAssign(db.Role(req.GetRoleName())) {
		return nil, newError(connect.CodePermissionDenied, "role cannot be assigned by you")
	}
	audit.Set(ctx, "role", req.GetRoleName())
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		if err := checkCanManageMember(ctx, q, req.GetWorkspaceId(), req.GetUserId()); err != nil {
			return err
		}
		return q.UpdateWorkspaceMember(ctx, &db.UpdateWorkspaceMemberParams{
			WorkspaceID: req.GetWorkspaceId(),
			UserID:      req.GetUserId(),
			RoleName:    req.GetRoleName(),
		})
	}); err != nil {
		return nil, err
	}

	return &nokkuv1.UpdateWorkspaceMemberResponse{}, nil
}

func (s *workspaceService) ListWorkspaceMembers(
	ctx context.Context,
	req *nokkuv1.ListWorkspaceMembersRequest,
) (*nokkuv1.ListWorkspaceMembersResponse, error) {
	var members []*db.ListWorkspaceMembersRow
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		members, err = q.ListWorkspaceMembers(ctx, &db.ListWorkspaceMembersParams{
			WorkspaceID: req.GetWorkspaceId(),
			Query:       req.Query,
			RoleName:    req.RoleName,
			Limit:       req.Limit,
			Offset:      req.Offset,
		})
		return err
	}); err != nil {
		return nil, err
	}

	var count int32
	protos := make([]*nokkuv1.WorkspaceMember, 0, len(members))
	for _, m := range members {
		count = m.TotalCount
		protos = append(protos, &nokkuv1.WorkspaceMember{
			Id:            &m.UserID,
			WorkspaceId:   &m.WorkspaceID,
			Name:          &m.Name,
			Email:         &m.Email,
			EmailVerified: &m.EmailVerified,
			Picture:       m.Picture,
			RoleName:      &m.RoleName,
			CreatedAt:     db.SafeTimestamp(&m.CreatedAt),
			UpdatedAt:     db.SafeTimestamp(&m.UpdatedAt),
		})
	}

	return &nokkuv1.ListWorkspaceMembersResponse{
		Members: protos,
		Total:   &count,
	}, nil
}

func (s *workspaceService) RemoveWorkspaceMember(
	ctx context.Context,
	req *nokkuv1.RemoveWorkspaceMemberRequest,
) (*nokkuv1.RemoveWorkspaceMemberResponse, error) {
	// Grants and team seats cascade from the membership.
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		if err := checkCanManageMember(ctx, q, req.GetWorkspaceId(), req.GetUserId()); err != nil {
			return err
		}
		return q.RemoveWorkspaceMember(ctx, &db.RemoveWorkspaceMemberParams{
			WorkspaceID: req.GetWorkspaceId(),
			UserID:      req.GetUserId(),
		})
	}); err != nil {
		return nil, err
	}

	return &nokkuv1.RemoveWorkspaceMemberResponse{}, nil
}

// checkCanManageMember also protects the owner, who is above everyone.
func checkCanManageMember(ctx context.Context, q db.Querier, workspaceID, userID string) error {
	m, err := q.GetWorkspaceMember(ctx, &db.GetWorkspaceMemberParams{
		WorkspaceID: workspaceID,
		UserID:      userID,
	})
	if err != nil {
		return err
	}
	if !callerRole(ctx).CanAssign(db.Role(m.RoleName)) {
		return db.ErrPermissionDenied
	}
	return nil
}

func checkWorkspaceOwner(ctx context.Context, q db.Querier, workspaceID string) error {
	ownerID, err := q.GetWorkspaceOwner(ctx, workspaceID)
	if err != nil {
		return err
	}
	if ownerID != actor.UserIDFromContext(ctx) {
		return errPermissionDenied
	}
	return nil
}

func (s *workspaceService) UpdateWorkspaceOwner(
	ctx context.Context,
	req *nokkuv1.UpdateWorkspaceOwnerRequest,
) (*nokkuv1.UpdateWorkspaceOwnerResponse, error) {
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		if err := checkWorkspaceOwner(ctx, q, req.GetWorkspaceId()); err != nil {
			return err
		}
		_, err := q.UpdateWorkspaceOwner(ctx, &db.UpdateWorkspaceOwnerParams{
			WorkspaceID: req.GetWorkspaceId(),
			NewOwnerID:  req.GetNewOwner(),
		})
		return err
	}); err != nil {
		return nil, err
	}

	return &nokkuv1.UpdateWorkspaceOwnerResponse{}, nil
}

// initializeWorkspace runs as a system tx since the workspace does not exist
// yet and cannot be pinned.
func (s *workspaceService) initializeWorkspace(
	ctx context.Context,
	params *db.CreateWorkspaceParams,
) (*nokkuv1.Workspace, error) {
	var workspace *db.CreateWorkspaceRow
	if err := s.cfg.Conn.WithTx(ctx, func(q *db.Queries) (err error) {
		workspace, err = q.CreateWorkspace(ctx, params)
		if err != nil {
			return err
		}

		ca, err := ssh.NewCA(
			nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_ED25519,
			0,
			0,
		)
		if err != nil {
			return err
		}

		_, err = q.CreateCA(ctx, &db.CreateCAParams{
			WorkspaceID:  workspace.ID,
			Name:         "Default CA",
			Description:  new("Default CA for workspace " + workspace.Name),
			Certificate:  string(ca.Certificate),
			PrivateKey:   ca.PrivateKey,
			PublicKey:    ca.PublicKey,
			SerialNumber: ca.SerialNumber,
			Subject:      ca.Subject,
			IsDefault:    true,
			NotBefore:    ca.NotBefore,
			NotAfter:     ca.NotAfter,
			KeyType:      ca.KeyType,
			KeyBits:      ca.KeyBits,
		})
		return err
	}); err != nil {
		return nil, err
	}

	return workspace.ToProto(), nil
}
