package iam

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/db"
)

func mapNotFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func (s *Service) ListCredentialsByType(ctx context.Context, typ Method) ([]*db.Credential, error) {
	var creds []*db.Credential
	err := s.asSelf(ctx, func(q *db.Queries) (err error) {
		creds, err = q.ListCredentialsByType(ctx, &db.ListCredentialsByTypeParams{
			UserID: actor.UserIDFromContext(ctx),
			Type:   string(typ),
		})
		return err
	})
	return creds, err
}

func (s *Service) GetCredential(ctx context.Context, id string) (*db.Credential, error) {
	var c *db.Credential
	err := s.asSelf(ctx, func(q *db.Queries) (err error) {
		c, err = q.GetCredential(ctx, &db.GetCredentialParams{UserID: actor.UserIDFromContext(ctx), ID: id})
		return err
	})
	if err != nil {
		return nil, mapNotFound(err)
	}
	return c, nil
}

func (s *Service) RenameCredential(ctx context.Context, id, label string) error {
	return s.asSelf(ctx, func(q *db.Queries) error {
		return q.RenameCredential(ctx, &db.RenameCredentialParams{
			UserID: actor.UserIDFromContext(ctx),
			ID:     id,
			Label:  label,
		})
	})
}

func (s *Service) DeleteCredential(ctx context.Context, id string) error {
	return s.asSelf(ctx, func(q *db.Queries) error {
		return q.DeleteCredential(ctx, &db.DeleteCredentialParams{UserID: actor.UserIDFromContext(ctx), ID: id})
	})
}

func (s *Service) PurgeProviderIdentities(ctx context.Context, typ Method, provider string) (int64, error) {
	return s.sys.DeleteCredentialsByProvider(ctx, &db.DeleteCredentialsByProviderParams{
		Type:     string(typ),
		Provider: provider,
	})
}

func (s *Service) UnlinkIdentity(ctx context.Context, provider string, methods ...Method) error {
	return s.asSelf(ctx, func(q *db.Queries) error {
		for _, m := range methods {
			if _, err := q.DeleteUserCredentialsByProvider(ctx, &db.DeleteUserCredentialsByProviderParams{
				UserID:   actor.UserIDFromContext(ctx),
				Type:     string(m),
				Provider: provider,
			}); err != nil {
				return err
			}
		}
		return nil
	})
}
