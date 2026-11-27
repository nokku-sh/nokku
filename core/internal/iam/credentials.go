package iam

import (
	"context"
	"slices"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/db"
)

// DeleteCredential keeps the last way in unless a sign-in link can replace it.
func (s *Service) DeleteCredential(ctx context.Context, id string) error {
	return s.conn.TenantTx(ctx, func(q *db.Queries) error {
		userID := actor.UserIDFromContext(ctx)
		ids, err := q.ListUserCredentialIDs(ctx, userID)
		if err != nil {
			return err
		}
		if !slices.Contains(ids, id) {
			return ErrNotFound
		}
		if len(ids) == 1 && !s.MagicLinkEnabled() {
			return ErrLastCredential
		}
		return q.DeleteCredential(ctx, &db.DeleteCredentialParams{UserID: userID, ID: id})
	})
}
