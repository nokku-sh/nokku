package iam

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/crypto"
	"github.com/nokku-sh/nokku/core/internal/db"
	emailverify "github.com/nokku-sh/nokku/core/internal/email"
)

const (
	// InviteTTL is how long an invite works, the mail says so.
	InviteTTL = 7 * 24 * time.Hour
	inviteURL = "/invite?token="
)

// Invite makes the one link that creates the account of email with role, in place of an earlier invite of the
// address. With mail the link goes out and is not returned. Without mail the admin gets it to hand over.
func (s *Service) Invite(ctx context.Context, email string, role nokkuv1.WorkspaceRole) (string, error) {
	email = NormalizeEmail(email)
	if err := emailverify.Verify(ctx, email, s.strict); err != nil {
		return "", ErrEmailRejected
	}
	var workspace string
	err := s.conn.TenantTx(ctx, func(q *db.Queries) error {
		ws, err := q.GetWorkspace(ctx)
		if err != nil {
			return err
		}
		if ws.Settings.GetEnforceSso() {
			return ErrSSORequired
		}
		workspace = ws.Name
		if _, err := q.GetUserByEmail(ctx, email); err == nil {
			return ErrEmailTaken
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		return s.checkSeat(ctx, q)
	})
	if err != nil {
		return "", err
	}
	raw, hash := crypto.NewToken(crypto.TokenInvite)
	link := baseURL(ctx) + inviteURL + raw
	// Mailed before it is stored, so a mail that fails or waits out its cooldown leaves the earlier invite working.
	if s.sendInvite != nil {
		if err := s.sendInvite(ctx, email, workspace, db.RoleLabel(role), link, InviteTTL); err != nil {
			if !errors.Is(err, emailverify.ErrCooldown) {
				slog.Warn("invite not sent", "error", err)
			}
			return "", errors.Join(ErrMailNotSent, err)
		}
		link = ""
	}
	// The mail is out, so the store must not die with the request's deadline.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	err = s.conn.TenantTx(ctx, func(q *db.Queries) error {
		if _, err := q.DeleteInvite(ctx, email); err != nil {
			return err
		}
		return q.PutInvite(ctx, &db.PutInviteParams{
			TokenHash: hash,
			Email:     &email,
			Role:      &role,
			ExpiresAt: s.now().Add(InviteTTL),
		})
	})
	if err != nil {
		return "", err
	}
	return link, nil
}

// LookupInvite reads an invite without spending it, so the page can show what it grants.
func (s *Service) LookupInvite(ctx context.Context, raw string) (*db.GetInviteRow, error) {
	hash, ok := crypto.TokenHash(raw, crypto.TokenInvite)
	if !ok {
		return nil, ErrInviteSpent
	}
	inv, err := s.conn.Tenant().GetInvite(ctx, hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInviteSpent
	}
	return inv, err
}

// AcceptInvite spends the invite, creates its account and signs it in. Nothing else spends it, so a mail scanner
// that opens every link burns no invite.
func (s *Service) AcceptInvite(ctx context.Context, raw, name string) (*db.User, *http.Cookie, error) {
	hash, ok := crypto.TokenHash(raw, crypto.TokenInvite)
	if !ok {
		return nil, nil, ErrInviteSpent
	}
	var u *db.User
	err := s.conn.TenantTx(ctx, func(q *db.Queries) error {
		inv, err := q.ConsumeInvite(ctx, hash)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInviteSpent
		}
		if err != nil {
			return err
		}
		// SSO may be required since the invite went out, and an invited account has no provider.
		ws, err := q.GetWorkspace(ctx)
		if err != nil {
			return err
		}
		if ws.Settings.GetEnforceSso() {
			return ErrSSORequired
		}
		u, err = s.createUser(ctx, q, db.CreateUserWithIDParams{
			Email: inv.Email, Name: strings.TrimSpace(name), Role: deref(inv.Role),
		})
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	s.record(ctx, event{
		Action: actionUserCreated, Kind: actor.KindUser, Method: MethodMagicLink, UserID: u.ID, Email: u.Email,
	})
	cookie, err := s.completeLogin(ctx, u, MethodMagicLink)
	if err != nil {
		return nil, nil, err
	}
	return u, cookie, nil
}
