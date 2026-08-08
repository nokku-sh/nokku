package api

import (
	"context"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/nokku-sh/nokku/internal/billing"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/meta"
)

type InvitationService struct {
	cfg *config.Config
}

func NewInvitationService(cfg *config.Config) *InvitationService {
	return &InvitationService{cfg: cfg}
}

func (s *InvitationService) GetInvitation(
	ctx context.Context,
	req *nokkuv1.GetInvitationRequest,
) (*nokkuv1.GetInvitationResponse, error) {
	token, err := crypto.Parse(req.GetToken())
	if err != nil {
		return nil, ErrInvalidInput
	}
	workspaceID := token.ID
	meta.SetAuditWorkspaceID(ctx, workspaceID)

	actor := meta.ActorFromContext(ctx)
	if actor.ID == "" || actor.Type != meta.ActorTypeUser {
		return nil, ErrBadCredentials
	}

	if _, err := s.cfg.Conn.Q.UserWorkspaceMember(ctx, &db.UserWorkspaceMemberParams{
		WorkspaceID: workspaceID,
		UserID:      actor.ID,
	}); err == nil {
		return nil, NewError(connect.CodeAborted, "you have already joined this workspace")
	}

	row, err := s.cfg.Conn.Q.GetWorkspace(ctx, workspaceID)
	if err != nil {
		return nil, DBError(err)
	}

	if !row.WorkspaceSetting.InviteTokenHash.Verify(req.GetToken()) {
		return nil, NewError(connect.CodeFailedPrecondition, "invalid invitation token")
	}

	return &nokkuv1.GetInvitationResponse{
		WorkspaceName:        &row.Workspace.Name,
		WorkspaceDescription: row.Workspace.Description,
		ExpiresAt:            db.SafeTimestamp(row.WorkspaceSetting.InviteExpiresAt),
	}, nil
}

func (s *InvitationService) AcceptInvitation(
	ctx context.Context,
	req *nokkuv1.AcceptInvitationRequest,
) (*nokkuv1.AcceptInvitationResponse, error) {
	token, err := crypto.Parse(req.GetToken())
	if err != nil {
		return nil, NewError(connect.CodeInvalidArgument, "invalid token")
	}
	workspaceID := token.ID
	meta.SetAuditWorkspaceID(ctx, workspaceID)

	userID := meta.UserIDFromContext(ctx)
	if userID == "" {
		return nil, ErrBadCredentials
	}

	if _, err := s.cfg.Conn.Q.UserWorkspaceMember(ctx, &db.UserWorkspaceMemberParams{
		WorkspaceID: workspaceID,
		UserID:      userID,
	}); err == nil {
		return nil, NewError(connect.CodeAborted, "you have already joined this workspace")
	}

	settings, err := s.cfg.Conn.Q.GetWorkspaceSettings(ctx, workspaceID)
	if err != nil {
		return nil, DBError(err)
	}
	if settings.InviteExpiresAt != nil && settings.InviteExpiresAt.Before(time.Now()) {
		return nil, NewError(connect.CodeFailedPrecondition, "invitation has expired")
	}
	if !settings.InviteTokenHash.Verify(req.GetToken()) {
		return nil, NewError(connect.CodeFailedPrecondition, "invalid invitation token")
	}

	if err := s.cfg.Billing.Check(ctx, workspaceID, billing.ResourceMembers); err != nil {
		return nil, err
	}

	user, err := s.cfg.Conn.Q.GetUserByID(ctx, meta.UserIDFromContext(ctx))
	if err != nil {
		return nil, ErrBadCredentials
	}

	if err = s.cfg.Conn.Q.AddWorkspaceMember(ctx, &db.AddWorkspaceMemberParams{
		WorkspaceID: workspaceID,
		UserID:      user.ID,
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.AcceptInvitationResponse{
		WorkspaceId: &workspaceID,
	}, nil
}

func (s *InvitationService) RefreshInviteToken(
	ctx context.Context,
	req *nokkuv1.RefreshInviteTokenRequest,
) (*nokkuv1.RefreshInviteTokenResponse, error) {
	meta.SetAuditWorkspaceID(ctx, req.GetWorkspaceId())

	token, err := crypto.NewToken(crypto.WithID(req.GetWorkspaceId()))
	if err != nil {
		return nil, ErrInternal
	}

	expiresAt := time.Now().Add(24 * time.Hour)
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		_, err = q.UpdateWorkspaceSettings(ctx, &db.UpdateWorkspaceSettingsParams{
			WorkspaceID:     req.GetWorkspaceId(),
			InviteTokenHash: token.Hash,
			InviteExpiresAt: &expiresAt,
		})
		return err
	}); err != nil {
		return nil, DBError(err)
	}

	link := fmt.Sprintf("%s?invite=%s", s.cfg.FullURL(), token.Plaintext)
	return &nokkuv1.RefreshInviteTokenResponse{
		Link:      &link,
		ExpiresAt: timestamppb.New(expiresAt),
	}, nil
}

func (s *InvitationService) RevokeInviteToken(
	ctx context.Context,
	req *nokkuv1.RevokeInviteTokenRequest,
) (*nokkuv1.RevokeInviteTokenResponse, error) {
	meta.SetAuditWorkspaceID(ctx, req.GetWorkspaceId())
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		_, err := q.UpdateWorkspaceSettings(ctx, &db.UpdateWorkspaceSettingsParams{
			WorkspaceID:     req.GetWorkspaceId(),
			InviteTokenHash: "",
			InviteExpiresAt: &time.Time{},
		})
		return err
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.RevokeInviteTokenResponse{}, nil
}
