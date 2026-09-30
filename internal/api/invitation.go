package api

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
)

var (
	errAlreadyMember = errors.New("already a member")
	errInviteInvalid = errors.New("invalid or expired invitation")
)

type InvitationService struct {
	cfg *config.Config
}

func NewInvitationService(cfg *config.Config) *InvitationService {
	return &InvitationService{cfg: cfg}
}

func inviteLookup(raw string) (*db.GetLiveTokenParams, error) {
	parsed, err := crypto.Parse(raw)
	if err != nil || parsed.ID == "" {
		return nil, errInviteInvalid
	}
	hash, err := crypto.HashToken(raw)
	if err != nil {
		return nil, errInviteInvalid
	}
	return &db.GetLiveTokenParams{ID: parsed.ID, Kind: nokkuv1.TokenKind_TOKEN_KIND_INVITE, TokenHash: hash}, nil
}

func inviteError(err error) error {
	switch {
	case errors.Is(err, errInviteInvalid):
		return NewError(connect.CodeFailedPrecondition, "invalid or expired invitation")
	case errors.Is(err, errAlreadyMember):
		return NewError(connect.CodeAborted, "you have already joined this workspace")
	default:
		return err
	}
}

func (s *InvitationService) GetInvitation(
	ctx context.Context,
	req *nokkuv1.GetInvitationRequest,
) (*nokkuv1.GetInvitationResponse, error) {
	userID := actor.UserIDFromContext(ctx)
	if userID == "" {
		return nil, ErrUserRequired
	}
	lookup, err := inviteLookup(req.GetToken())
	if err != nil {
		return nil, inviteError(err)
	}

	// System tx since the joiner is not a member yet. The token is checked
	// first, so nothing leaks without a valid one.
	var (
		token     *db.WorkspaceToken
		workspace *db.Workspace
	)
	if err := s.cfg.Conn.WithTx(ctx, func(q *db.Queries) (err error) {
		token, err = q.GetLiveToken(ctx, lookup)
		if err != nil || (token.MaxUses != nil && token.Uses >= *token.MaxUses) {
			return errInviteInvalid
		}
		workspace, err = q.GetWorkspace(ctx, token.WorkspaceID)
		if err != nil {
			return err
		}
		if _, err := q.UserWorkspaceMember(ctx, &db.UserWorkspaceMemberParams{
			WorkspaceID: token.WorkspaceID,
			UserID:      userID,
		}); err == nil {
			return errAlreadyMember
		}
		return nil
	}); err != nil {
		return nil, inviteError(err)
	}

	return &nokkuv1.GetInvitationResponse{
		WorkspaceName:        &workspace.Name,
		WorkspaceDescription: workspace.Description,
		ExpiresAt:            db.SafeTimestamp(token.ExpiresAt),
		RoleName:             token.RoleName,
	}, nil
}

func (s *InvitationService) AcceptInvitation(
	ctx context.Context,
	req *nokkuv1.AcceptInvitationRequest,
) (*nokkuv1.AcceptInvitationResponse, error) {
	userID := actor.UserIDFromContext(ctx)
	if userID == "" {
		return nil, ErrUserRequired
	}
	lookup, err := inviteLookup(req.GetToken())
	if err != nil {
		return nil, inviteError(err)
	}

	// Existing members are turned away before the token spends a use.
	var workspaceID string
	err = s.cfg.Conn.WithTx(ctx, func(q *db.Queries) error {
		token, err := q.GetLiveToken(ctx, lookup)
		if err != nil {
			return errInviteInvalid
		}
		workspaceID = token.WorkspaceID
		if _, err := q.UserWorkspaceMember(ctx, &db.UserWorkspaceMemberParams{
			WorkspaceID: workspaceID,
			UserID:      userID,
		}); err == nil {
			return errAlreadyMember
		}
		if _, err := q.RedeemToken(ctx, &db.RedeemTokenParams{
			ID:        lookup.ID,
			Kind:      lookup.Kind,
			TokenHash: lookup.TokenHash,
		}); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errInviteInvalid
			}
			return err
		}
		return s.cfg.IAM.EnsureMember(ctx, q, userID, workspaceID, *token.RoleName)
	})
	if err != nil {
		return nil, inviteError(err)
	}
	return &nokkuv1.AcceptInvitationResponse{WorkspaceId: &workspaceID}, nil
}
