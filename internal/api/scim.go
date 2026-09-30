package api

import (
	"context"

	"github.com/nokku-sh/nokku/internal/audit"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/iam"
)

type sCIMService struct {
	cfg *config.Config
}

func newSCIMService(cfg *config.Config) *sCIMService {
	return &sCIMService{cfg: cfg}
}

func (s *sCIMService) CreateSCIMToken(
	ctx context.Context,
	req *nokkuv1.CreateSCIMTokenRequest,
) (*nokkuv1.CreateSCIMTokenResponse, error) {
	if err := requireVerifiedDomain(ctx, s.cfg.IAM, "a SCIM connector", req.GetWorkspaceId()); err != nil {
		return nil, err
	}
	tok, plaintext, err := s.cfg.IAM.IssueSCIMToken(ctx, req.GetWorkspaceId(), req.GetLabel())
	if err != nil {
		return nil, err
	}
	entry := scimTokenToProto(tok)
	audit.SetTarget(ctx, entry.GetId())
	return &nokkuv1.CreateSCIMTokenResponse{
		Token:   &plaintext,
		Entry:   entry,
		BaseUrl: new(s.cfg.FullURL() + "/scim/v2/" + req.GetWorkspaceId()),
	}, nil
}

func (s *sCIMService) ListSCIMTokens(
	ctx context.Context,
	req *nokkuv1.ListSCIMTokensRequest,
) (*nokkuv1.ListSCIMTokensResponse, error) {
	tokens, err := s.cfg.IAM.ListSCIMTokens(ctx, req.GetWorkspaceId())
	if err != nil {
		return nil, err
	}
	out := make([]*nokkuv1.SCIMToken, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, scimTokenToProto(t))
	}
	return &nokkuv1.ListSCIMTokensResponse{Tokens: out}, nil
}

func (s *sCIMService) DeleteSCIMToken(
	ctx context.Context,
	req *nokkuv1.DeleteSCIMTokenRequest,
) (*nokkuv1.DeleteSCIMTokenResponse, error) {
	if err := s.cfg.IAM.RevokeSCIMToken(ctx, req.GetWorkspaceId(), req.GetTokenId()); err != nil {
		return nil, err
	}
	return &nokkuv1.DeleteSCIMTokenResponse{}, nil
}

func scimTokenToProto(t iam.SCIMToken) *nokkuv1.SCIMToken {
	return &nokkuv1.SCIMToken{
		Id:         &t.ID,
		Label:      &t.Label,
		CreatedAt:  db.SafeTimestamp(&t.CreatedAt),
		LastUsedAt: db.SafeTimestamp(t.LastUsedAt),
	}
}
