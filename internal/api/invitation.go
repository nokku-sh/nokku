package api

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/mizuchilabs/kagi"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/nokku-sh/nokku/internal/audit"
	"github.com/nokku-sh/nokku/internal/auth"
	"github.com/nokku-sh/nokku/internal/billing"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
)

var (
	errAlreadyMember = errors.New("already a member")
	errInviteExpired = errors.New("invitation expired")
	errInviteInvalid = errors.New("invalid invitation token")
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
	audit.SetWorkspaceID(ctx, workspaceID)

	actor, _ := kagi.PrincipalFromContext(ctx)
	if actor.SubjectID == "" || actor.Kind != auth.ActorTypeUser {
		return nil, ErrBadCredentials
	}

	// System transaction: the invitee is not a member of the workspace yet,
	// so no tenant context can be established. The invite token (validated
	// below against its hash) authorizes this read.
	var workspace *db.Workspace
	if err := s.cfg.Conn.WithTx(ctx, func(q *db.Queries) (err error) {
		if _, err := q.UserWorkspaceMember(ctx, &db.UserWorkspaceMemberParams{
			WorkspaceID: workspaceID,
			UserID:      actor.SubjectID,
		}); err == nil {
			return errAlreadyMember
		}

		workspace, err = q.GetWorkspace(ctx, workspaceID)
		return err
	}); errors.Is(err, errAlreadyMember) {
		return nil, NewError(connect.CodeAborted, "you have already joined this workspace")
	} else if err != nil {
		return nil, DBError(err)
	}

	if !workspace.InviteTokenHash.Verify(req.GetToken()) {
		return nil, NewError(connect.CodeFailedPrecondition, "invalid invitation token")
	}

	return &nokkuv1.GetInvitationResponse{
		WorkspaceName:        &workspace.Name,
		WorkspaceDescription: workspace.Description,
		ExpiresAt:            db.SafeTimestamp(workspace.InviteExpiresAt),
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
	audit.SetWorkspaceID(ctx, workspaceID)

	userID := auth.UserIDFromContext(ctx)
	if userID == "" {
		return nil, ErrBadCredentials
	}

	if err := s.cfg.Billing.Check(ctx, workspaceID, billing.ResourceMembers); err != nil {
		return nil, err
	}

	// System transaction: the joiner is not a member yet. The invite token
	// is validated against its stored hash before the membership is added.
	err = s.cfg.Conn.WithTx(ctx, func(q *db.Queries) error {
		if _, err := q.UserWorkspaceMember(ctx, &db.UserWorkspaceMemberParams{
			WorkspaceID: workspaceID,
			UserID:      userID,
		}); err == nil {
			return errAlreadyMember
		}

		settings, err := q.GetWorkspace(ctx, workspaceID)
		if err != nil {
			return err
		}
		if settings.InviteExpiresAt != nil && settings.InviteExpiresAt.Before(time.Now()) {
			return errInviteExpired
		}
		if !settings.InviteTokenHash.Verify(req.GetToken()) {
			return errInviteInvalid
		}

		return q.AddWorkspaceMember(ctx, &db.AddWorkspaceMemberParams{
			WorkspaceID: workspaceID,
			UserID:      userID,
		})
	})
	switch {
	case errors.Is(err, errAlreadyMember):
		return nil, NewError(connect.CodeAborted, "you have already joined this workspace")
	case errors.Is(err, errInviteExpired):
		return nil, NewError(connect.CodeFailedPrecondition, "invitation has expired")
	case errors.Is(err, errInviteInvalid):
		return nil, NewError(connect.CodeFailedPrecondition, "invalid invitation token")
	case err != nil:
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
	token, err := crypto.NewToken(crypto.WithID(req.GetWorkspaceId()))
	if err != nil {
		return nil, ErrInternal
	}

	expiresAt := time.Now().Add(24 * time.Hour)
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		return q.UpdateInviteToken(ctx, &db.UpdateInviteTokenParams{
			WorkspaceID:     req.GetWorkspaceId(),
			InviteTokenHash: token.Hash,
			InviteExpiresAt: &expiresAt,
		})
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
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		return q.UpdateInviteToken(ctx, &db.UpdateInviteTokenParams{
			WorkspaceID:     req.GetWorkspaceId(),
			InviteTokenHash: "",
			InviteExpiresAt: &time.Time{},
		})
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.RevokeInviteTokenResponse{}, nil
}
