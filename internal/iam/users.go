package iam

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/db"
)

// normalizeEmail matches the schema's email = lower(email) check.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func mapUserError(err error) error {
	if db.IsUniqueViolation(err) {
		return ErrEmailTaken
	}
	return err
}

func mapNotFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// GetUser is the signed-in user.
func (s *Service) GetUser(ctx context.Context) (*db.User, error) {
	id := actor.UserIDFromContext(ctx)
	if id == "" {
		return nil, ErrNotFound
	}
	return s.getUser(ctx, id)
}

func (s *Service) getUser(ctx context.Context, id string) (*db.User, error) {
	u, err := s.conn.Tenant().GetUser(ctx, id)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return u, nil
}

func (s *Service) GetUserByEmail(ctx context.Context, email string) (*db.User, error) {
	u, err := s.conn.Tenant().GetUserByEmail(ctx, normalizeEmail(email))
	if err != nil {
		return nil, mapNotFound(err)
	}
	return u, nil
}

func (s *Service) UpdateSelf(ctx context.Context, name, picture *string) (*db.User, error) {
	u, err := s.conn.Tenant().UpdateUser(ctx, &db.UpdateUserParams{
		ID:      actor.UserIDFromContext(ctx),
		Name:    name,
		Picture: picture,
	})
	if err != nil {
		return nil, mapNotFound(err)
	}
	return u, nil
}

// DeleteSelf refuses the owner, the workspace would be left without one.
func (s *Service) DeleteSelf(ctx context.Context) error {
	u, err := s.GetUser(ctx)
	if err != nil {
		return err
	}
	if u.Role == string(db.RoleOwner) {
		return ErrOwner
	}
	if err := s.conn.Tenant().DeleteUser(ctx, u.ID); err != nil {
		return err
	}
	s.record(ctx, event{Action: actionUserDeleted, Kind: actor.KindUser, UserID: u.ID, Email: u.Email})
	return nil
}

// RevokeUser ends every session of a user, for a deactivation.
func (s *Service) RevokeUser(ctx context.Context, userID string) (int64, error) {
	n, err := s.revokeSubject(ctx, userID)
	if err == nil && n > 0 {
		s.record(ctx, event{Action: actionSessionRevoked, Kind: actor.KindUser, UserID: userID})
	}
	return n, err
}
