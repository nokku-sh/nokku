package api

import (
	"context"
	"time"
	"uuid"

	"connectrpc.com/connect"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
)

type TokenService struct {
	cfg *config.Config
}

func NewTokenService(cfg *config.Config) *TokenService {
	return &TokenService{cfg: cfg}
}

// CreateToken mints an enroll or invite token. The plaintext is
// "<id>_<secret>" and is returned once, only its hash is stored.
func (s *TokenService) CreateToken(
	ctx context.Context,
	req *nokkuv1.CreateTokenRequest,
) (*nokkuv1.CreateTokenResponse, error) {
	params := &db.CreateWorkspaceTokenParams{
		ID:          uuid.NewV7().String(),
		WorkspaceID: req.GetWorkspaceId(),
		Kind:        req.GetKind(),
		Label:       req.GetLabel(),
		MaxUses:     req.MaxUses,
	}
	if req.GetTtl() != nil {
		params.ExpiresAt = new(time.Now().Add(req.GetTtl().AsDuration()))
	}
	switch req.GetKind() {
	case nokkuv1.TokenKind_TOKEN_KIND_ENROLL:
		if req.GetRoleName() != "" {
			return nil, NewError(connect.CodeInvalidArgument, "enroll tokens take no role")
		}
		params.AutoApprove = req.GetAutoApprove()
		params.CaID = req.CaId
	case nokkuv1.TokenKind_TOKEN_KIND_INVITE:
		if req.GetAutoApprove() || req.GetCaId() != "" {
			return nil, NewError(connect.CodeInvalidArgument, "invite tokens take only a role")
		}
		role := req.GetRoleName()
		if role == "" {
			role = "viewer"
		}
		if !db.IsUserRole(role) {
			return nil, NewError(connect.CodeInvalidArgument, "role cannot be granted by invite")
		}
		params.RoleName = &role
	case nokkuv1.TokenKind_TOKEN_KIND_UNSPECIFIED:
		return nil, ErrInvalidInput
	default:
		return nil, ErrInvalidInput
	}

	token, err := crypto.NewToken(crypto.WithID(params.ID))
	if err != nil {
		return nil, ErrInternal
	}
	params.TokenHash = token.Hash

	var created *db.WorkspaceToken
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		created, err = q.CreateWorkspaceToken(ctx, params)
		return err
	}); err != nil {
		return nil, DBError(err)
	}
	return &nokkuv1.CreateTokenResponse{
		Token:  created.ToProto(),
		Secret: &token.Plaintext,
	}, nil
}

func (s *TokenService) ListTokens(
	ctx context.Context,
	req *nokkuv1.ListTokensRequest,
) (*nokkuv1.ListTokensResponse, error) {
	var tokens []*db.WorkspaceToken
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		tokens, err = q.ListWorkspaceTokens(ctx, &db.ListWorkspaceTokensParams{
			WorkspaceID: req.GetWorkspaceId(),
			Kind:        req.GetKind(),
		})
		return err
	}); err != nil {
		return nil, DBError(err)
	}
	return &nokkuv1.ListTokensResponse{Tokens: db.TokensToProto(tokens)}, nil
}

// DeleteToken revokes a token. Daemons and members it already brought in
// stay.
func (s *TokenService) DeleteToken(
	ctx context.Context,
	req *nokkuv1.DeleteTokenRequest,
) (*nokkuv1.DeleteTokenResponse, error) {
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		return q.DeleteWorkspaceToken(ctx, req.GetId())
	}); err != nil {
		return nil, DBError(err)
	}
	return &nokkuv1.DeleteTokenResponse{}, nil
}
