package iam

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/db"
)

// mapNotFound translates a no-rows error into ErrNotFound.
func mapNotFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// Credential helpers over the unified credentials table. Types, providers,
// and subjects are strings at this boundary; the methods constants are for
// auth logic, not storage.

// ListCredentialsByType returns the request user's credentials of one type.
func (s *Service) ListCredentialsByType(ctx context.Context, typ Method) ([]*db.Credential, error) {
	var creds []*db.Credential
	err := s.asSelf(ctx, func(q *db.Queries) (err error) {
		creds, err = q.ListCredentialsByType(ctx, &db.ListCredentialsByTypeParams{
			UserID: UserIDFromContext(ctx),
			Type:   string(typ),
		})
		return err
	})
	return creds, err
}

// GetCredential returns one credential of the request user, or ErrNotFound.
func (s *Service) GetCredential(ctx context.Context, id string) (*db.Credential, error) {
	var c *db.Credential
	err := s.asSelf(ctx, func(q *db.Queries) (err error) {
		c, err = q.GetCredential(ctx, &db.GetCredentialParams{UserID: UserIDFromContext(ctx), ID: id})
		return err
	})
	if err != nil {
		return nil, mapNotFound(err)
	}
	return c, nil
}

// RenameCredential updates the display label of one of the request user's
// credentials.
func (s *Service) RenameCredential(ctx context.Context, id, label string) error {
	return s.asSelf(ctx, func(q *db.Queries) error {
		return q.RenameCredential(ctx, &db.RenameCredentialParams{
			UserID: UserIDFromContext(ctx),
			ID:     id,
			Label:  label,
		})
	})
}

// DeleteCredential removes one of the request user's credentials.
func (s *Service) DeleteCredential(ctx context.Context, id string) error {
	return s.asSelf(ctx, func(q *db.Queries) error {
		return q.DeleteCredential(ctx, &db.DeleteCredentialParams{UserID: UserIDFromContext(ctx), ID: id})
	})
}

// PurgeProviderIdentities removes every identity linked through one
// provider. Subjects are only unique within an issuer, so links must not
// survive an issuer change.
func (s *Service) PurgeProviderIdentities(ctx context.Context, typ Method, provider string) (int64, error) {
	return s.sys.DeleteCredentialsByProvider(ctx, &db.DeleteCredentialsByProviderParams{
		Type:     string(typ),
		Provider: provider,
	})
}

// UnlinkIdentity removes the request user's linked identities from one
// provider, across the given identity methods.
func (s *Service) UnlinkIdentity(ctx context.Context, provider string, methods ...Method) error {
	return s.asSelf(ctx, func(q *db.Queries) error {
		for _, m := range methods {
			if _, err := q.DeleteUserCredentialsByProvider(ctx, &db.DeleteUserCredentialsByProviderParams{
				UserID:   UserIDFromContext(ctx),
				Type:     string(m),
				Provider: provider,
			}); err != nil {
				return err
			}
		}
		return nil
	})
}
