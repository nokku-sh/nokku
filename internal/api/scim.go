package api

import (
	"context"

	"github.com/nokku-sh/nokku/internal/audit"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/iam"
)

// SCIMService manages workspace connector tokens. The SCIM endpoint itself
// is mounted at /scim/v2/{workspace_id} and authenticates with these
// tokens; the service is the only place they are minted, listed, and
// revoked, and the plaintext is shown exactly once at creation.

type SCIMService struct {
	cfg *config.Config
}

func NewSCIMService(cfg *config.Config) *SCIMService {
	return &SCIMService{cfg: cfg}
}

func (s *SCIMService) CreateSCIMToken(
	ctx context.Context,
	req *nokkuv1.CreateSCIMTokenRequest,
) (*nokkuv1.CreateSCIMTokenResponse, error) {
	// The connector mints accounts on any userName it is told to create.
	// Without a verified domain, a token holder could squat arbitrary
	// emails at scale, so SCIM setup demands the same domain proof as SSO.
	if err := requireVerifiedDomain(ctx, s.cfg.IAM, "a SCIM connector", req.GetWorkspaceId()); err != nil {
		return nil, err
	}
	tok, plaintext, err := s.cfg.IAM.IssueSCIMToken(ctx, req.GetWorkspaceId(), req.GetLabel())
	if err != nil {
		return nil, DBError(err)
	}
	token := plaintext
	entry := scimTokenToProto(tok)
	audit.SetTarget(ctx, entry.GetId())
	baseURL := s.cfg.FullURL() + "/scim/v2/" + req.GetWorkspaceId()
	return &nokkuv1.CreateSCIMTokenResponse{
		Token:   &token,
		Entry:   entry,
		BaseUrl: &baseURL,
	}, nil
}

func (s *SCIMService) ListSCIMTokens(
	ctx context.Context,
	req *nokkuv1.ListSCIMTokensRequest,
) (*nokkuv1.ListSCIMTokensResponse, error) {
	tokens, err := s.cfg.IAM.ListSCIMTokens(ctx, req.GetWorkspaceId())
	if err != nil {
		return nil, DBError(err)
	}
	out := make([]*nokkuv1.SCIMToken, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, scimTokenToProto(t))
	}
	return &nokkuv1.ListSCIMTokensResponse{Tokens: out}, nil
}

func (s *SCIMService) DeleteSCIMToken(
	ctx context.Context,
	req *nokkuv1.DeleteSCIMTokenRequest,
) (*nokkuv1.DeleteSCIMTokenResponse, error) {
	if err := s.cfg.IAM.RevokeSCIMToken(ctx, req.GetWorkspaceId(), req.GetTokenId()); err != nil {
		return nil, DBError(err)
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
