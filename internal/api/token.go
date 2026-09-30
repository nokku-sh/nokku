package api

import (
	"cmp"
	"context"
	"time"
	"uuid"

	"github.com/nokku-sh/nokku/internal/audit"

	"connectrpc.com/connect"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
)

type tokenService struct {
	cfg *config.Config
}

func newTokenService(cfg *config.Config) *tokenService {
	return &tokenService{cfg: cfg}
}

// CreateToken returns the "<id>_<secret>" plaintext once, only its hash is stored.
func (s *tokenService) CreateToken(
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
			return nil, newError(connect.CodeInvalidArgument, "enroll tokens take no role")
		}
		params.AutoApprove = req.GetAutoApprove()
		params.CaID = req.CaId
	case nokkuv1.TokenKind_TOKEN_KIND_INVITE:
		if req.GetAutoApprove() || req.GetCaId() != "" {
			return nil, newError(connect.CodeInvalidArgument, "invite tokens take only a role")
		}
		role := cmp.Or(req.GetRoleName(), string(db.RoleMember))
		if !callerRole(ctx).CanAssign(db.Role(role)) {
			return nil, newError(connect.CodePermissionDenied, "role cannot be granted by you")
		}
		params.RoleName = &role
		audit.Set(ctx, "role", role)
	case nokkuv1.TokenKind_TOKEN_KIND_UNSPECIFIED:
		return nil, errInvalidInput
	default:
		return nil, errInvalidInput
	}

	token, err := crypto.NewToken(crypto.WithID(params.ID))
	if err != nil {
		return nil, errInternal
	}
	params.TokenHash = token.Hash

	var created *db.WorkspaceToken
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		created, err = q.CreateWorkspaceToken(ctx, params)
		return err
	}); err != nil {
		return nil, err
	}
	audit.SetTarget(ctx, created.ID)
	return &nokkuv1.CreateTokenResponse{
		Token:  created.ToProto(),
		Secret: &token.Plaintext,
	}, nil
}

func (s *tokenService) ListTokens(
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
		return nil, err
	}
	return &nokkuv1.ListTokensResponse{Tokens: db.TokensToProto(tokens)}, nil
}

// DeleteToken keeps the daemons and members the token already brought in.
func (s *tokenService) DeleteToken(
	ctx context.Context,
	req *nokkuv1.DeleteTokenRequest,
) (*nokkuv1.DeleteTokenResponse, error) {
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		return q.DeleteWorkspaceToken(ctx, req.GetId())
	}); err != nil {
		return nil, err
	}
	return &nokkuv1.DeleteTokenResponse{}, nil
}
