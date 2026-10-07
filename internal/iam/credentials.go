package iam

import (
	"context"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/db"
)

// ListCredentials is every passkey and linked identity of the signed-in user.
func (s *Service) ListCredentials(ctx context.Context) ([]*db.Credential, error) {
	var creds []*db.Credential
	err := s.inWorkspace(ctx, func(q *db.Queries, ws string) (err error) {
		creds, err = q.ListUserCredentials(ctx, &db.ListUserCredentialsParams{
			WorkspaceID: ws,
			UserID:      actor.UserIDFromContext(ctx),
		})
		return err
	})
	return creds, err
}

func (s *Service) ListCredentialsByType(ctx context.Context, typ Method) ([]*db.Credential, error) {
	var creds []*db.Credential
	err := s.inWorkspace(ctx, func(q *db.Queries, ws string) (err error) {
		creds, err = q.ListCredentialsByType(ctx, &db.ListCredentialsByTypeParams{
			WorkspaceID: ws,
			UserID:      actor.UserIDFromContext(ctx),
			Type:        string(typ),
		})
		return err
	})
	return creds, err
}

func (s *Service) RenameCredential(ctx context.Context, id, label string) error {
	return s.inWorkspace(ctx, func(q *db.Queries, ws string) error {
		return q.RenameCredential(ctx, &db.RenameCredentialParams{
			WorkspaceID: ws,
			UserID:      actor.UserIDFromContext(ctx),
			ID:          id,
			Label:       label,
		})
	})
}

// DeleteCredential removes a passkey or a linked identity. The last way in
// stays unless a sign-in link can replace it.
func (s *Service) DeleteCredential(ctx context.Context, id string) error {
	return s.inWorkspace(ctx, func(q *db.Queries, ws string) error {
		userID := actor.UserIDFromContext(ctx)
		creds, err := q.ListUserCredentials(ctx, &db.ListUserCredentialsParams{WorkspaceID: ws, UserID: userID})
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
		return q.DeleteCredential(ctx, &db.DeleteCredentialParams{WorkspaceID: ws, UserID: userID, ID: id})
	})
}

// PurgeProviderIdentities unlinks every identity a provider vouched for.
func (s *Service) PurgeProviderIdentities(ctx context.Context, provider string) (int64, error) {
	var n int64
	err := s.inWorkspace(ctx, func(q *db.Queries, ws string) (err error) {
		n, err = q.DeleteCredentialsByProvider(ctx, &db.DeleteCredentialsByProviderParams{
			WorkspaceID: ws,
			Type:        string(MethodOIDC),
			Provider:    provider,
		})
		return err
	})
	return n, err
}
