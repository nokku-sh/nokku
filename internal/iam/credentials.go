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

// ListCredentialsByType returns the user's credentials of one method type.
func (s *Service) ListCredentialsByType(
	ctx context.Context,
	userID string,
	typ Method,
) ([]*db.Credential, error) {
	return s.q.ListCredentialsByType(ctx, &db.ListCredentialsByTypeParams{
		UserID: userID,
		Type:   string(typ),
	})
}

// GetCredential returns one credential of the user, or ErrNotFound.
func (s *Service) GetCredential(ctx context.Context, userID, id string) (*db.Credential, error) {
	c, err := s.q.GetCredential(ctx, &db.GetCredentialParams{UserID: userID, ID: id})
	if err != nil {
		return nil, mapNotFound(err)
	}
	return c, nil
}

// RenameCredential updates a credential's display label.
func (s *Service) RenameCredential(ctx context.Context, userID, id, label string) error {
	return s.q.RenameCredential(ctx, &db.RenameCredentialParams{
		UserID: userID,
		ID:     id,
		Label:  label,
	})
}

// DeleteCredential removes one credential of the user.
func (s *Service) DeleteCredential(ctx context.Context, userID, id string) error {
	return s.q.DeleteCredential(ctx, &db.DeleteCredentialParams{UserID: userID, ID: id})
}

// DeleteCredentialsByProvider removes every credential of one type and
// provider for the user and reports how many went. A subject is only unique
// within its issuer, so stale mappings must not survive an issuer change.
func (s *Service) DeleteCredentialsByProvider(
	ctx context.Context,
	userID string,
	typ Method,
	provider string,
) (int64, error) {
	return s.q.DeleteUserCredentialsByProvider(ctx, &db.DeleteUserCredentialsByProviderParams{
		UserID:   userID,
		Type:     string(typ),
		Provider: provider,
	})
}

// deleteCredentialsOfType removes every credential of one method type for the
// user. q is a parameter so callers inside a transaction delete through that
// transaction's querier.
func deleteCredentialsOfType(ctx context.Context, q db.Querier, userID string, typ Method) error {
	creds, err := q.ListCredentialsByType(ctx, &db.ListCredentialsByTypeParams{
		UserID: userID,
		Type:   string(typ),
	})
	if err != nil {
		return err
	}
	for _, c := range creds {
		if err := q.DeleteCredential(
			ctx,
			&db.DeleteCredentialParams{UserID: userID, ID: c.ID},
		); err != nil {
			return err
		}
	}
	return nil
}
