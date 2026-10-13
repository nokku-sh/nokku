package iam

import (
	"context"
	"slices"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/db"
)

func (s *Service) ListCredentials(ctx context.Context) ([]*db.Credential, error) {
	return s.conn.Tenant().ListUserCredentials(ctx, actor.UserIDFromContext(ctx))
}

func (s *Service) ListCredentialsByType(ctx context.Context, typ Method) ([]*db.Credential, error) {
	return s.conn.Tenant().ListCredentialsByType(ctx, &db.ListCredentialsByTypeParams{
		UserID: actor.UserIDFromContext(ctx),
		Type:   string(typ),
	})
}

func (s *Service) RenameCredential(ctx context.Context, id, label string) error {
	return s.conn.Tenant().RenameCredential(ctx, &db.RenameCredentialParams{
		UserID: actor.UserIDFromContext(ctx),
		ID:     id,
		Label:  label,
	})
}

// DeleteCredential keeps the last way in unless a sign-in link can replace it.
func (s *Service) DeleteCredential(ctx context.Context, id string) error {
	return s.conn.TenantTx(ctx, func(q *db.Queries) error {
		userID := actor.UserIDFromContext(ctx)
		creds, err := q.ListUserCredentials(ctx, userID)
		if err != nil {
			return err
		}
		if !slices.ContainsFunc(creds, func(c *db.Credential) bool { return c.ID == id }) {
			return ErrNotFound
		}
		if len(creds) == 1 && !s.MagicLinkEnabled() {
			return ErrLastCredential
		}
		return q.DeleteCredential(ctx, &db.DeleteCredentialParams{UserID: userID, ID: id})
	})
}
