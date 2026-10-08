package iam

import (
	"context"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/db"
)

// ListCredentials is every passkey and linked identity of the signed-in user.
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

// DeleteCredential removes a passkey or a linked identity. The last way in
// stays unless a sign-in link can replace it.
func (s *Service) DeleteCredential(ctx context.Context, id string) error {
	return s.conn.TenantTx(ctx, func(q *db.Queries) error {
		userID := actor.UserIDFromContext(ctx)
		creds, err := q.ListUserCredentials(ctx, userID)
		if err != nil {
			return err
		}
		remaining := 0
		found := false
		for _, c := range creds {
			if c.ID == id {
				found = true
				continue
			}
			if c.Type != string(MethodSCIM) {
				remaining++
			}
		}
		if !found {
			return ErrNotFound
		}
		if remaining == 0 && !s.MagicLinkEnabled() {
			return ErrLastCredential
		}
		return q.DeleteCredential(ctx, &db.DeleteCredentialParams{UserID: userID, ID: id})
	})
}

// PurgeProviderIdentities unlinks every identity a provider vouched for.
func (s *Service) PurgeProviderIdentities(ctx context.Context, provider string) (int64, error) {
	return s.conn.Tenant().DeleteCredentialsByProvider(ctx, &db.DeleteCredentialsByProviderParams{
		Type:     string(MethodOIDC),
		Provider: provider,
	})
}
