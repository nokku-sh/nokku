package api

import (
	"context"
	"errors"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/meta"
	"github.com/nokku-sh/nokku/internal/ssh"
	"github.com/nokku-sh/nokku/internal/util"
)

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
	var workspace *db.GetWorkspaceRow
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		workspace, err = q.GetWorkspace(ctx, req.GetWorkspaceId())
		return err
	}); err != nil {
		return nil, ErrNotFound
	}
	return &nokkuv1.GetWorkspaceResponse{
		Workspace: workspace.ToProto(),
	}, nil
}

func (s *WorkspaceService) CreateWorkspace(
	ctx context.Context,
	req *nokkuv1.CreateWorkspaceRequest,
) (*nokkuv1.CreateWorkspaceResponse, error) {
	user, err := s.cfg.Conn.Q.GetUserByID(ctx, meta.UserIDFromContext(ctx))
	if err != nil {
		return nil, ErrBadCredentials
	}

	// Check if the user has reached the maximum number of workspaces
	count, err := s.cfg.Conn.Q.CountWorkspacesByOwner(ctx, user.ID)
	if err != nil {
		return nil, ErrInternal
	}
	if count >= 5 {
		return nil, NewError(connect.CodeResourceExhausted, "maximum number of workspaces reached")
	}

	workspace, err := s.initializeWorkspace(ctx, &db.CreateWorkspaceParams{
		Name:        req.GetName(),
		Description: req.Description,
		CreatedBy:   user.ID,
	})
	if err != nil || workspace == nil {
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
	meta.SetAuditWorkspaceID(ctx, req.GetWorkspaceId())

	var workspace *db.Workspace
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		workspace, err = q.UpdateWorkspace(ctx, &db.UpdateWorkspaceParams{
			WorkspaceID: req.GetWorkspaceId(),
			Name:        req.Name,
			Description: req.Description,
		})
		return err
	}); err != nil {
		return nil, ErrInternal
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
	// Revoke subscription
	if s.cfg.Billing != nil {
		if err := s.cfg.Billing.Cancel(ctx, req.GetWorkspaceId(), true, ""); err != nil {
			return nil, ErrInternal
		}
	}

	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		return q.DeleteWorkspace(ctx, req.GetWorkspaceId())
	}); err != nil {
		return nil, ErrInternal
	}

	return &nokkuv1.DeleteWorkspaceResponse{}, nil
}

func (s *WorkspaceService) ListWorkspaces(
	ctx context.Context,
	_ *nokkuv1.ListWorkspacesRequest,
) (*nokkuv1.ListWorkspacesResponse, error) {
	var workspaces []*db.ListWorkspacesRow
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		workspaces, err = q.ListWorkspaces(ctx)
		return err
	}); err != nil {
		if errors.Is(err, db.ErrNoWorkspaces) {
			return &nokkuv1.ListWorkspacesResponse{}, nil
		}
		return nil, ErrInternal
	}

	return &nokkuv1.ListWorkspacesResponse{
		Workspaces: db.ListWorkspacesToProto(workspaces),
	}, nil
}

func (s *WorkspaceService) UpdateWorkspaceSettings(
	ctx context.Context,
	req *nokkuv1.UpdateWorkspaceSettingsRequest,
) (*nokkuv1.UpdateWorkspaceSettingsResponse, error) {
	meta.SetAuditWorkspaceID(ctx, req.GetWorkspaceId())

	var settings *db.WorkspaceSetting
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		params := &db.UpdateWorkspaceSettingsParams{WorkspaceID: req.GetWorkspaceId()}
		if req.EnrollAutoApprove != nil {
			params.EnrollAutoApprove = req.EnrollAutoApprove
		}

		settings, err = q.UpdateWorkspaceSettings(ctx, params)
		return err
	}); err != nil {
		return nil, ErrInternal
	}

	return &nokkuv1.UpdateWorkspaceSettingsResponse{
		Settings: settings.ToProto(),
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
		return nil, ErrInternal
	}

	return &nokkuv1.GetWorkspaceMemberResponse{
		Member: member.ToProto(),
	}, nil
}

func (s *WorkspaceService) UpdateWorkspaceMember(
	ctx context.Context,
	req *nokkuv1.UpdateWorkspaceMemberRequest,
) (*nokkuv1.UpdateWorkspaceMemberResponse, error) {
	meta.SetAuditWorkspaceID(ctx, req.GetWorkspaceId())

	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		return q.UpdateWorkspaceMember(ctx, &db.UpdateWorkspaceMemberParams{
			WorkspaceID: req.GetWorkspaceId(),
			UserID:      req.GetUserId(),
			RoleName:    req.GetRoleName(),
		})
	}); err != nil {
		return nil, ErrInternal
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
		return nil, ErrInternal
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
	meta.SetAuditWorkspaceID(ctx, req.GetWorkspaceId())

	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		rows, err := q.RemoveWorkspaceMember(ctx, &db.RemoveWorkspaceMemberParams{
			WorkspaceID: req.GetWorkspaceId(),
			UserID:      req.GetUserId(),
		})
		if err != nil {
			return ErrNotFound
		}
		if rows == 0 {
			return ErrNotFound
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return &nokkuv1.RemoveWorkspaceMemberResponse{}, nil
}

func (s *WorkspaceService) UpdateWorkspaceOwner(
	ctx context.Context,
	req *nokkuv1.UpdateWorkspaceOwnerRequest,
) (*nokkuv1.UpdateWorkspaceOwnerResponse, error) {
	meta.SetAuditWorkspaceID(ctx, req.GetWorkspaceId())

	var ownerID string
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		var err error
		ownerID, err = q.GetWorkspaceOwner(ctx, req.GetWorkspaceId())
		if err != nil {
			return err
		}
		if ownerID != meta.UserIDFromContext(ctx) {
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
		return nil, ErrInternal
	}

	return &nokkuv1.UpdateWorkspaceOwnerResponse{}, nil
}

func (s *WorkspaceService) SubscribeWorkspaceEvents(
	ctx context.Context,
	req *nokkuv1.SubscribeWorkspaceEventsRequest,
	stream *connect.ServerStream[nokkuv1.SubscribeWorkspaceEventsResponse],
) error {
	workspaceID := req.GetWorkspaceId()
	meta.SetAuditWorkspaceID(ctx, workspaceID)

	if _, err := s.cfg.Conn.Q.UserWorkspaceMember(ctx, &db.UserWorkspaceMemberParams{
		WorkspaceID: workspaceID,
		UserID:      meta.UserIDFromContext(ctx),
	}); err != nil {
		return ErrPermissionDenied
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

func (s *WorkspaceService) initializeWorkspace(
	ctx context.Context,
	params *db.CreateWorkspaceParams,
) (*nokkuv1.Workspace, error) {
	workspace, err := s.cfg.Conn.Q.CreateWorkspace(ctx, params)
	if err != nil {
		return nil, ErrInternal
	}

	// Create a unscoped transaction
	if err := s.cfg.Conn.WithTx(ctx, func(q *db.Queries) error {
		// Generate SAML SP key pair and certificate
		samlKeyPair, err := util.CreateSAMLKeyPair(workspace.ID)
		if err != nil {
			return err
		}
		if _, err = q.UpdateSAMLProvider(ctx, &db.UpdateSAMLProviderParams{
			WorkspaceID:     workspace.ID,
			SpPrivateKey:    crypto.EncryptedBytes(samlKeyPair.PrivateKey),
			SpCertificate:   &samlKeyPair.Certificate,
			SpCertExpiresAt: &samlKeyPair.ExpiresAt,
		}); err != nil {
			return err
		}

		// Create default certificates
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
		slog.Debug("failed to create workspace", "error", err)
		if err := s.cfg.Conn.Q.DeleteWorkspace(ctx, workspace.ID); err != nil {
			slog.Debug("failed to delete workspace", "error", err)
			return nil, ErrInternal
		}
		return nil, err
	}

	return workspace.ToProto(), nil
}
