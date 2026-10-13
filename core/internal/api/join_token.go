package api

import (
	"cmp"
	"context"
	"time"
	"uuid"

	"github.com/nokku-sh/nokku/core/internal/audit"

	"connectrpc.com/connect"

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
		if req.GetRetireAfter() != nil && !req.GetEphemeral() {
			return nil, newError(connect.CodeInvalidArgument, "retire_after needs an ephemeral token")
		}
		params.AutoApprove = req.GetAutoApprove()
		params.CaID = req.CaId
		params.Tags = req.GetTags()
		if req.GetEphemeral() {
			// A pending box would retire before anyone approves it.
			params.AutoApprove = true
			retire := defaultRetireAfter
			if req.GetRetireAfter() != nil {
				retire = req.GetRetireAfter().AsDuration()
			}
			params.RetireAfter = &retire
		}
	case nokkuv1.JoinTokenKind_JOIN_TOKEN_KIND_INVITE:
		if req.GetAutoApprove() || req.GetCaId() != "" || req.GetEphemeral() ||
			len(req.GetTags()) > 0 || len(req.GetGrants()) > 0 {
			return nil, newError(connect.CodeInvalidArgument, "invite tokens take only a role")
		}
		// An invite ends in a mailed link. Without mail or under required SSO it would be a dead one.
		if !s.cfg.Email.HasSMTP() {
			return nil, newError(connect.CodeFailedPrecondition, "invitations need email, set NOKKU_SMTP_HOST first")
		}
		ws, err := s.cfg.Conn.Tenant().GetWorkspace(ctx)
		if err != nil {
			return nil, err
		}
		if ws.Settings.GetEnforceSso() {
			return nil, errSSORequired
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

	var created *db.JoinToken
	err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		if created, err = q.CreateJoinToken(ctx, params); err != nil {
			return err
		}
		return addJoinTokenGrants(ctx, q, created.ID, req.GetGrants())
	})
	if db.IsForeignKeyViolation(err) {
		return nil, newError(connect.CodeInvalidArgument, "a grant names a subject that does not exist")
	}
	if err != nil {
		return nil, err
	}
	audit.SetTarget(ctx, created.ID)
	out := created.ToProto()
	out.Grants = req.GetGrants()
	return &nokkuv1.CreateJoinTokenResponse{
		Token:  out,
		Secret: &token.Plaintext,
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
	req *nokkuv1.ListJoinTokensRequest,
) (*nokkuv1.ListJoinTokensResponse, error) {
	var (
		tokens []*db.JoinToken
		grants []*db.ListJoinTokenGrantsRow
	)
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		if tokens, err = q.ListJoinTokens(ctx, req.GetKind()); err != nil {
			return err
		}
		grants, err = q.ListJoinTokenGrants(ctx)
		return err
	}); err != nil {
		return nil, err
	}
	return &nokkuv1.ListJoinTokensResponse{Tokens: db.JoinTokensToProto(tokens, grants)}, nil
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
