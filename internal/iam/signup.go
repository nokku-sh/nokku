package iam

import (
	"cmp"
	"context"
	"errors"
	"uuid"

	"github.com/jackc/pgx/v5"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
)

// signupData rides in a signup token or a passkey ceremony until the
// account exists.
type signupData struct {
	Name     string                `json:"name"`
	Role     nokkuv1.WorkspaceRole `json:"role"`
	InviteID string                `json:"invite_id,omitempty"`
}

// LookupInvite resolves an invite link in this workspace without spending it.
func (s *Service) LookupInvite(ctx context.Context, raw string) (*db.WorkspaceToken, error) {
	var tok *db.WorkspaceToken
	err := s.conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		tok, err = lookupInvite(ctx, q, raw)
		return err
	})
	return tok, err
}

func lookupInvite(ctx context.Context, q *db.Queries, raw string) (*db.WorkspaceToken, error) {
	parsed, err := crypto.Parse(raw)
	if err != nil || parsed.ID == "" {
		return nil, ErrInviteSpent
	}
	hash := crypto.HashToken(raw)
	tok, err := q.GetLiveToken(ctx, &db.GetLiveTokenParams{
		ID:        parsed.ID,
		Kind:      nokkuv1.TokenKind_TOKEN_KIND_INVITE,
		TokenHash: hash,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInviteSpent
	}
	if err != nil {
		return nil, err
	}
	if tok.MaxUses != nil && tok.Uses >= *tok.MaxUses {
		return nil, ErrInviteSpent
	}
	return tok, nil
}

// createUser is the one way an account comes to be. It redeems the invite
// when one is named and checks the seat cap in the same tx, so parallel
// joins cannot oversell the last seat. The owner is exempt from the cap. An
// empty ID gets a fresh one, a passkey ceremony brings the id it reserved.
func (s *Service) createUser(
	ctx context.Context,
	q *db.Queries,
	p db.CreateUserWithIDParams,
	inviteID string,
) (*db.User, error) {
	p.ID = cmp.Or(p.ID, uuid.NewV7().String())
	p.Email = normalizeEmail(p.Email)
	p.Role = cmp.Or(p.Role, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	if inviteID != "" {
		tok, err := q.RedeemTokenByID(ctx, &db.RedeemTokenByIDParams{
			ID:   inviteID,
			Kind: nokkuv1.TokenKind_TOKEN_KIND_INVITE,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInviteSpent
		}
		if err != nil {
			return nil, err
		}
		p.Role = cmp.Or(deref(tok.Role), p.Role)
	}
	if s.canJoin != nil && p.Role != nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER {
		if _, err := q.GetWorkspaceForUpdate(ctx); err != nil {
			return nil, err
		}
		ws := actor.WorkspaceIDFromContext(ctx)
		used, err := q.CountActiveUsers(ctx, ws)
		if err != nil {
			return nil, err
		}
		if err := s.canJoin(ctx, ws, used); err != nil {
			return nil, errors.Join(ErrSeatLimit, err)
		}
	}
	u, err := q.CreateUserWithID(ctx, &p)
	if err != nil {
		return nil, mapUserError(err)
	}
	return u, nil
}

// CreateOwner makes the first user of a fresh workspace. The seat cap does
// not apply, there is nobody to count yet.
func (s *Service) CreateOwner(ctx context.Context, email, name string) (*db.User, error) {
	var u *db.User
	err := s.conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		u, err = s.createUser(ctx, q, db.CreateUserWithIDParams{
			Email: email, Name: name, Role: nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER,
		}, "")
		return err
	})
	if err != nil {
		return nil, err
	}
	s.record(ctx, event{Action: actionUserCreated, Kind: actor.KindUser, UserID: u.ID, Email: u.Email})
	return u, nil
}
