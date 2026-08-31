package api

import (
	"context"

	"connectrpc.com/connect"
	"github.com/mizuchilabs/kagi"

	"github.com/nokku-sh/nokku/internal/auth"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
)

// UserService only identifies service-account principals. Everything else
// about the account (profile, password, passkeys, linked identities, backup
// codes, sessions, deletion) is served by kagi's account surface under
// /auth/account, which the frontend calls directly.
type UserService struct {
	cfg *config.Config
}

func NewUserService(cfg *config.Config) *UserService {
	return &UserService{cfg: cfg}
}

func (s *UserService) Whoami(
	ctx context.Context,
	_ *nokkuv1.WhoamiRequest,
) (*nokkuv1.WhoamiResponse, error) {
	actor, _ := kagi.PrincipalFromContext(ctx)
	if actor.Kind != auth.ActorTypeServiceAccount {
		return nil, NewError(
			connect.CodeUnimplemented,
			"identity is served by the auth layer (/auth/account)",
		)
	}

	var result *db.ServiceAccount
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		result, err = q.GetServiceAccount(ctx, actor.SubjectID)
		return err
	}); err != nil {
		return nil, DBError(err)
	}
	if result == nil {
		return nil, ErrNotFound
	}
	tenant, _ := kagi.TenantFromContext(ctx)
	used := lastUsedBySubject(ctx, s.cfg.Auth.Keys, string(tenant))
	sa := result.ToProto()
	stampLastUsedAt(sa, used)
	return &nokkuv1.WhoamiResponse{
		ServiceAccount: sa,
	}, nil
}
