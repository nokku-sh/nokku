package api

import (
	"context"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/mizuchilabs/kagi"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/nokku-sh/nokku/internal/audit"
	"github.com/nokku-sh/nokku/internal/auth"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/ssh"
)

func DefaultWorkspaceSettings() *nokkuv1.WorkspaceSettings {
	return &nokkuv1.WorkspaceSettings{
		EnrollAutoApprove: new(true),
		DefaultDaemonConfig: &nokkuv1.DaemonConfig{
			RecordSessions:       new(true),
			AllowForwarding:      new(true),
			AllowAgentForwarding: new(true),
			GatewayPorts:         new(false),
			MaxSessions:          new(int32(10)),
			MaxConnections:       new(int32(100)),
			ClientAliveInterval:  durationpb.New(60 * time.Second),
		},
	}
}

type WorkspaceService struct {
	cfg *config.Config
}

func NewWorkspaceService(cfg *config.Config) *WorkspaceService {
	return &WorkspaceService{cfg: cfg}
}

func (s *WorkspaceService) GetWorkspace(
	ctx context.Context,
	req *nokkuv1.GetWorkspaceRequest,
) (*nokkuv1.GetWorkspaceResponse, error) {
	var workspace *db.Workspace
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		workspace, err = q.GetWorkspace(ctx, req.GetWorkspaceId())
		return err
	}); err != nil {
		return nil, DBError(err)
	}
	return &nokkuv1.GetWorkspaceResponse{
		Workspace: workspace.ToProto(),
	}, nil
}

func (s *WorkspaceService) CreateWorkspace(
	ctx context.Context,
	req *nokkuv1.CreateWorkspaceRequest,
) (*nokkuv1.CreateWorkspaceResponse, error) {
	user, err := s.cfg.Conn.Q.GetUserByID(ctx, auth.UserIDFromContext(ctx))
	if err != nil {
		return nil, DBError(err)
	}

	var count int32
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		count, err = q.CountWorkspacesByOwner(ctx, user.ID)
		return err
	}); err != nil {
		return nil, DBError(err)
	}
	if count >= 5 {
		return nil, NewError(connect.CodeResourceExhausted, "maximum number of workspaces reached")
	}

	workspace, err := s.initializeWorkspace(ctx, &db.CreateWorkspaceParams{
		Name:        req.GetName(),
		Description: req.Description,
		CreatedBy:   user.ID,
		Settings:    DefaultWorkspaceSettings(),
	})
	if err != nil {
		return nil, DBError(err)
	}
	if workspace == nil {
		return nil, ErrInternal
	}

	return &nokkuv1.CreateWorkspaceResponse{
		Workspace: workspace,
	}, nil
}

func (s *WorkspaceService) UpdateWorkspace(
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
		return nil, DBError(err)
	}
	if workspace == nil {
		return nil, ErrNotFound
	}

	return &nokkuv1.UpdateWorkspaceResponse{
		Workspace: workspace.ToProto(),
	}, nil
}

func (s *WorkspaceService) DeleteWorkspace(
	ctx context.Context,
	req *nokkuv1.DeleteWorkspaceRequest,
) (*nokkuv1.DeleteWorkspaceResponse, error) {
	if s.cfg.Billing.Enabled() {
		if err := s.cfg.Billing.Cancel(ctx, req.GetWorkspaceId(), true, ""); err != nil {
			return nil, ErrInternal
		}
	}

	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		return q.DeleteWorkspace(ctx, req.GetWorkspaceId())
	}); err != nil {
		return nil, DBError(err)
	}
	return &nokkuv1.DeleteWorkspaceResponse{}, nil
}

func (s *WorkspaceService) ListWorkspaces(
	ctx context.Context,
	_ *nokkuv1.ListWorkspacesRequest,
) (*nokkuv1.ListWorkspacesResponse, error) {
	var workspaces []*db.Workspace
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		workspaces, err = q.ListWorkspaces(ctx)
		return err
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.ListWorkspacesResponse{
		Workspaces: db.ListWorkspacesToProto(workspaces),
	}, nil
}

func (s *WorkspaceService) GetWorkspaceMember(
	ctx context.Context,
	req *nokkuv1.GetWorkspaceMemberRequest,
) (*nokkuv1.GetWorkspaceMemberResponse, error) {
	if req.GetWorkspaceId() == "" {
		return nil, ErrInvalidInput
	}

	var member *db.GetWorkspaceMemberRow
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		member, err = q.GetWorkspaceMember(ctx, &db.GetWorkspaceMemberParams{
			WorkspaceID: req.GetWorkspaceId(),
			UserID:      req.GetUserId(),
		})
		return err
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.GetWorkspaceMemberResponse{
		Member: member.ToProto(),
	}, nil
}

func (s *WorkspaceService) UpdateWorkspaceMember(
	ctx context.Context,
	req *nokkuv1.UpdateWorkspaceMemberRequest,
) (*nokkuv1.UpdateWorkspaceMemberResponse, error) {
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		return q.UpdateWorkspaceMember(ctx, &db.UpdateWorkspaceMemberParams{
			WorkspaceID: req.GetWorkspaceId(),
			UserID:      req.GetUserId(),
			RoleName:    req.GetRoleName(),
		})
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.UpdateWorkspaceMemberResponse{}, nil
}

func (s *WorkspaceService) ListWorkspaceMembers(
	ctx context.Context,
	req *nokkuv1.ListWorkspaceMembersRequest,
) (*nokkuv1.ListWorkspaceMembersResponse, error) {
	var members []*db.ListWorkspaceMembersRow
	var count int32
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		count, err = q.CountMembers(ctx, &db.CountMembersParams{
			WorkspaceID: req.GetWorkspaceId(),
			Query:       req.Query,
		})
		if err != nil {
			return err
		}

		members, err = q.ListWorkspaceMembers(ctx, &db.ListWorkspaceMembersParams{
			WorkspaceID: req.GetWorkspaceId(),
			Query:       req.Query,
			RoleName:    req.RoleName,
			Limit:       req.Limit,
			Offset:      req.Offset,
		})
		return err
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.ListWorkspaceMembersResponse{
		Members: db.WorkspaceMembersToProto(members),
		Total:   &count,
	}, nil
}

func (s *WorkspaceService) RemoveWorkspaceMember(
	ctx context.Context,
	req *nokkuv1.RemoveWorkspaceMemberRequest,
) (*nokkuv1.RemoveWorkspaceMemberResponse, error) {
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		return q.RemoveWorkspaceMember(ctx, &db.RemoveWorkspaceMemberParams{
			WorkspaceID: req.GetWorkspaceId(),
			UserID:      req.GetUserId(),
		})
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.RemoveWorkspaceMemberResponse{}, nil
}

func (s *WorkspaceService) UpdateWorkspaceOwner(
	ctx context.Context,
	req *nokkuv1.UpdateWorkspaceOwnerRequest,
) (*nokkuv1.UpdateWorkspaceOwnerResponse, error) {
	var ownerID string
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		var err error
		ownerID, err = q.GetWorkspaceOwner(ctx, req.GetWorkspaceId())
		if err != nil {
			return err
		}
		if ownerID != auth.UserIDFromContext(ctx) {
			return ErrPermissionDenied
		}
		_, err = q.UpdateWorkspaceOwner(ctx, &db.UpdateWorkspaceOwnerParams{
			WorkspaceID: req.GetWorkspaceId(),
			NewOwnerID:  req.GetNewOwner(),
		})
		return err
	}); err != nil {
		if errors.Is(err, ErrPermissionDenied) {
			return nil, ErrPermissionDenied
		}
		return nil, DBError(err)
	}

	return &nokkuv1.UpdateWorkspaceOwnerResponse{}, nil
}

func (s *WorkspaceService) SubscribeWorkspaceEvents(
	ctx context.Context,
	req *nokkuv1.SubscribeWorkspaceEventsRequest,
	stream *connect.ServerStream[nokkuv1.SubscribeWorkspaceEventsResponse],
) error {
	workspaceID := req.GetWorkspaceId()
	audit.SetWorkspaceID(ctx, workspaceID)

	// Streaming handlers bypass the unary interceptor's workspace promotion,
	// so pin the workspace here and let the scoped transaction verify
	// membership before events start flowing.
	ctx = kagi.WithTenant(ctx, kagi.TenantID(workspaceID))
	if err := s.cfg.Conn.WithWorkspace(ctx, func(_ *db.Queries) error {
		return nil
	}); err != nil {
		return DBError(err)
	}

	msgCh := s.cfg.Pool.SubscribeEvents(workspaceID, req.GetEventTypes())
	defer s.cfg.Pool.UnsubscribeEvents(workspaceID, msgCh)

	for {
		select {
		case <-ctx.Done():
			return nil
		case event := <-msgCh:
			if err := stream.Send(event); err != nil {
				return err
			}
		}
	}
}

// Helpers --------------------------------------------------------------------

// initializeWorkspace creates a workspace with all of its dependent records.
// This deliberately runs as a system transaction (bypassing RLS): the
// workspace does not exist yet, so no tenant context can be pinned for it.
func (s *WorkspaceService) initializeWorkspace(
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

		if _, err = q.CreateCA(ctx, &db.CreateCAParams{
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
		}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return workspace.ToProto(), nil
}
