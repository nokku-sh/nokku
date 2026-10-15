package api

import (
	"context"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/iam"
)

type scimService struct {
	cfg *config.Config
}

func (s *scimService) CreateSCIMToken(
	ctx context.Context,
	req *nokkuv1.CreateSCIMTokenRequest,
) (*nokkuv1.CreateSCIMTokenResponse, error) {
	tok, plaintext, err := s.cfg.IAM.IssueToken(ctx, iam.TokenParams{
		Kind:   actor.KindSCIM,
		Method: iam.MethodSCIM,
		Label:  req.GetLabel(),
	})
	if err != nil {
		return nil, err
	}
	audit.SetTarget(ctx, tok.ID)
	return &nokkuv1.CreateSCIMTokenResponse{
		Token:   &plaintext,
		Entry:   scimTokenToProto(tok),
		BaseUrl: new(iam.SCIMBaseURL(ctx)),
	}, nil
}

func (s *scimService) ListSCIMTokens(
	ctx context.Context,
	_ *nokkuv1.ListSCIMTokensRequest,
) (*nokkuv1.ListSCIMTokensResponse, error) {
	tokens, err := s.cfg.Conn.Tenant().ListSCIMTokens(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*nokkuv1.SCIMToken, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, scimTokenToProto(t))
	}
	return &nokkuv1.ListSCIMTokensResponse{Tokens: out, BaseUrl: new(iam.SCIMBaseURL(ctx))}, nil
}

func (s *scimService) DeleteSCIMToken(
	ctx context.Context,
	req *nokkuv1.DeleteSCIMTokenRequest,
) (*nokkuv1.DeleteSCIMTokenResponse, error) {
	if err := s.cfg.Conn.Tenant().DeleteSCIMToken(ctx, req.GetId()); err != nil {
		return nil, err
	}
	return &nokkuv1.DeleteSCIMTokenResponse{}, nil
}

func scimTokenToProto(t *db.AccessToken) *nokkuv1.SCIMToken {
	return &nokkuv1.SCIMToken{
		Id:         &t.ID,
		Label:      &t.Label,
		CreatedAt:  db.SafeTimestamp(&t.CreatedAt),
		LastUsedAt: db.SafeTimestamp(t.LastSeenAt),
	}
}
