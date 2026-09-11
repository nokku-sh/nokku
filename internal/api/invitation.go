package api

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/nokku-sh/nokku/internal/iam"

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
	ctx = iam.AnnotateTenant(ctx, workspaceID)

	actor, _ := iam.PrincipalFromContext(ctx)
	if actor.ID == "" || actor.Kind != iam.KindUser {
		return nil, ErrBadCredentials
	}

	// The joiner is not a member yet, so this runs as a system transaction:
	// RLS would deny the workspace read to nokku_app. The token is verified
	// before any state checks so no information leaks without a valid token.
	var workspace *db.Workspace
	if err := s.cfg.Conn.WithTx(ctx, func(q *db.Queries) error {
		var err error
		workspace, err = q.GetWorkspace(ctx, workspaceID)
		if err != nil {
			return err
		}
		if !workspace.InviteTokenHash.Verify(req.GetToken()) {
			return errInviteInvalid
		}
		if _, err := q.UserWorkspaceMember(ctx, &db.UserWorkspaceMemberParams{
			WorkspaceID: workspaceID,
			UserID:      actor.ID,
		}); err == nil {
			return errAlreadyMember
		}
		return nil
	}); errors.Is(err, errInviteInvalid) {
		return nil, NewError(connect.CodeFailedPrecondition, "invalid invitation token")
	} else if errors.Is(err, errAlreadyMember) {
		return nil, NewError(connect.CodeAborted, "you have already joined this workspace")
	} else if err != nil {
		return nil, DBError(err)
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
	ctx = iam.AnnotateTenant(ctx, workspaceID)

	userID := iam.UserIDFromContext(ctx)
	if userID == "" {
		return nil, ErrBadCredentials
	}

	// System transaction: the joiner is not a member yet. The workspace row
	// is locked so concurrent joins serialize before the seat count, and the
	// token is verified before any state checks.
	err = s.cfg.Conn.WithTx(ctx, func(q *db.Queries) error {
		settings, err := q.GetWorkspaceForUpdate(ctx, workspaceID)
		if err != nil {
			return err
		}
		if !settings.InviteTokenHash.Verify(req.GetToken()) {
			return errInviteInvalid
		}
		if settings.InviteExpiresAt != nil && settings.InviteExpiresAt.Before(time.Now()) {
			return errInviteExpired
		}
		if _, err := q.UserWorkspaceMember(ctx, &db.UserWorkspaceMemberParams{
			WorkspaceID: workspaceID,
			UserID:      userID,
		}); err == nil {
			return errAlreadyMember
		}

		// The gate and the insert share this transaction, so the workspace row
		// lock the seat count depends on is held across both.
		return s.cfg.IAM.EnsureMember(ctx, q, userID, workspaceID)
	})
	switch {
	case err == nil:
	case errors.Is(err, errAlreadyMember):
		return nil, NewError(connect.CodeAborted, "you have already joined this workspace")
	case errors.Is(err, errInviteExpired):
		return nil, NewError(connect.CodeFailedPrecondition, "invitation has expired")
	case errors.Is(err, errInviteInvalid):
		return nil, NewError(connect.CodeFailedPrecondition, "invalid invitation token")
	default:
		if _, ok := errors.AsType[*connect.Error](err); ok {
			return nil, err
		}
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
