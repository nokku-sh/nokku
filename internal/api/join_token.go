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

type joinTokenService struct {
	cfg *config.Config
}

// CreateJoinToken returns the "<id>_<secret>" plaintext once, only its hash is stored.
func (s *joinTokenService) CreateJoinToken(
	ctx context.Context,
	req *nokkuv1.CreateJoinTokenRequest,
) (*nokkuv1.CreateJoinTokenResponse, error) {
	params := &db.CreateJoinTokenParams{
		ID:      uuid.NewV7().String(),
		Kind:    req.GetKind(),
		Label:   req.GetLabel(),
		MaxUses: req.MaxUses,
	}
	if req.GetTtl() != nil {
		params.ExpiresAt = new(time.Now().Add(req.GetTtl().AsDuration()))
	}
	switch req.GetKind() {
	case nokkuv1.JoinTokenKind_JOIN_TOKEN_KIND_ENROLL:
		if req.GetRole() != nokkuv1.WorkspaceRole_WORKSPACE_ROLE_UNSPECIFIED {
			return nil, newError(connect.CodeInvalidArgument, "enroll tokens take no role")
		}
		params.AutoApprove = req.GetAutoApprove()
		params.CaID = req.CaId
	case nokkuv1.JoinTokenKind_JOIN_TOKEN_KIND_INVITE:
		if req.GetAutoApprove() || req.GetCaId() != "" {
			return nil, newError(connect.CodeInvalidArgument, "invite tokens take only a role")
		}
		role := cmp.Or(req.GetRole(), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
		if !db.CanAssign(callerRole(ctx), role) {
			return nil, newError(connect.CodePermissionDenied, "role cannot be granted by you")
		}
		params.Role = &role
		audit.Set(ctx, "role", db.RoleLabel(role))
	case nokkuv1.JoinTokenKind_JOIN_TOKEN_KIND_UNSPECIFIED:
		return nil, errInvalidInput
	default:
		return nil, errInvalidInput
	}

	token := crypto.NewToken(params.ID)
	params.TokenHash = token.Hash

	created, err := s.cfg.Conn.Tenant().CreateJoinToken(ctx, params)
	if err != nil {
		return nil, err
	}
	audit.SetTarget(ctx, created.ID)
	return &nokkuv1.CreateJoinTokenResponse{
		Token:  created.ToProto(),
		Secret: &token.Plaintext,
	}, nil
}

func (s *joinTokenService) ListJoinTokens(
	ctx context.Context,
	req *nokkuv1.ListJoinTokensRequest,
) (*nokkuv1.ListJoinTokensResponse, error) {
	tokens, err := s.cfg.Conn.Tenant().ListJoinTokens(ctx, req.GetKind())
	if err != nil {
		return nil, err
	}
	return &nokkuv1.ListJoinTokensResponse{Tokens: db.JoinTokensToProto(tokens)}, nil
}

// DeleteJoinToken keeps the daemons and members the token already brought in.
func (s *joinTokenService) DeleteJoinToken(
	ctx context.Context,
	req *nokkuv1.DeleteJoinTokenRequest,
) (*nokkuv1.DeleteJoinTokenResponse, error) {
	if err := s.cfg.Conn.Tenant().DeleteJoinToken(ctx, req.GetId()); err != nil {
		return nil, err
	}
	return &nokkuv1.DeleteJoinTokenResponse{}, nil
}
