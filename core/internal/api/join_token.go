package api

import (
	"context"
	"time"

	"github.com/nokku-sh/nokku/core/internal/audit"

	"connectrpc.com/connect/v2"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/crypto"
	"github.com/nokku-sh/nokku/core/internal/db"
)

type joinTokenService struct {
	cfg *config.Config
}

// defaultRetireAfter is how long an ephemeral daemon may be away before the sweep deletes it.
const defaultRetireAfter = 15 * time.Minute

// CreateJoinToken returns the plaintext once, only its hash is stored.
func (s *joinTokenService) CreateJoinToken(
	ctx context.Context,
	req *nokkuv1.CreateJoinTokenRequest,
) (*nokkuv1.CreateJoinTokenResponse, error) {
	if req.GetRetireAfter() != nil && !req.GetEphemeral() {
		return nil, newError(connect.CodeInvalidArgument, "retire_after needs an ephemeral token")
	}
	params := &db.CreateJoinTokenParams{
		Label:       req.GetLabel(),
		MaxUses:     req.MaxUses,
		AutoApprove: req.GetAutoApprove(),
		Tags:        req.GetTags(),
	}
	if req.GetTtl() != nil {
		params.ExpiresAt = new(time.Now().Add(req.GetTtl().AsDuration()))
	}
	if req.GetEphemeral() {
		// A pending box would retire before anyone approves it.
		params.AutoApprove = true
		retire := defaultRetireAfter
		if req.GetRetireAfter() != nil {
			retire = req.GetRetireAfter().AsDuration()
		}
		params.RetireAfter = &retire
	}
	secret, hash := crypto.NewToken(crypto.TokenEnroll)
	params.TokenHash = hash

	var created *db.JoinToken
	err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		if created, err = q.CreateJoinToken(ctx, params); err != nil {
			return err
		}
		if err = addJoinTokenGrants(ctx, q, created.ID, req.GetGrants()); db.IsForeignKeyViolation(err) {
			return newError(connect.CodeInvalidArgument, "a grant names a subject that does not exist")
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	audit.SetTarget(ctx, created.ID)
	out := created.ToProto()
	out.Grants = req.GetGrants()
	return &nokkuv1.CreateJoinTokenResponse{
		Token:  out,
		Secret: &secret,
	}, nil
}

// addJoinTokenGrants stores one row per subject, like AddSubjects does for a target account.
func addJoinTokenGrants(ctx context.Context, q *db.Queries, tokenID string, grants []*nokkuv1.JoinTokenGrant) error {
	for _, g := range grants {
		subjects := map[string][]string{
			db.SubjectKindUser:           g.GetUserIds(),
			db.SubjectKindTeam:           g.GetTeamIds(),
			db.SubjectKindServiceAccount: g.GetServiceAccountIds(),
		}
		for kind, ids := range subjects {
			for _, id := range ids {
				if err := q.AddJoinTokenGrant(ctx, &db.AddJoinTokenGrantParams{
					TokenID:     tokenID,
					Username:    g.GetUsername(),
					SubjectKind: kind,
					SubjectID:   id,
				}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (s *joinTokenService) ListJoinTokens(
	ctx context.Context,
	_ *nokkuv1.ListJoinTokensRequest,
) (*nokkuv1.ListJoinTokensResponse, error) {
	var (
		tokens []*db.JoinToken
		grants []*db.ListJoinTokenGrantsRow
	)
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		if tokens, err = q.ListJoinTokens(ctx); err != nil {
			return err
		}
		grants, err = q.ListJoinTokenGrants(ctx)
		return err
	}); err != nil {
		return nil, err
	}
	return &nokkuv1.ListJoinTokensResponse{Tokens: db.JoinTokensToProto(tokens, grants)}, nil
}

// DeleteJoinToken keeps the daemons the token already brought in.
func (s *joinTokenService) DeleteJoinToken(
	ctx context.Context,
	req *nokkuv1.DeleteJoinTokenRequest,
) (*nokkuv1.DeleteJoinTokenResponse, error) {
	if err := s.cfg.Conn.Tenant().DeleteJoinToken(ctx, req.GetId()); err != nil {
		return nil, err
	}
	return &nokkuv1.DeleteJoinTokenResponse{}, nil
}
