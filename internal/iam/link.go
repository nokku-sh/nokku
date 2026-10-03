package iam

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/db"
)

var (
	errIdentityLinked   = errors.New("iam: identity already linked to another account")
	errIdentityRejected = errors.New("iam: identity rejected")
)

type flowLinkOptions struct {
	ProviderID string
	// WorkspaceID is empty for social providers. An enterprise provider only
	// vouches for its verified domains, a social one needs a verified email.
	WorkspaceID   string
	Subject       string
	Email         string
	EmailVerified bool
	// Enterprise logins refresh the name on every login, the IdP owns it.
	Name            string
	Picture         string
	JITProvisioning bool
	// LinkUserID skips the email lookup and links to that signed-in user.
	LinkUserID string
}

type linker struct {
	svc      *Service
	credType Method
}

// Resolve also joins the user to the provider's workspace.
func (l *linker) Resolve(ctx context.Context, opts flowLinkOptions) (*db.User, error) {
	u, err := l.resolve(ctx, opts)
	if err != nil {
		l.svc.record(ctx, Event{
			Action:      ActionLoginDenied,
			Method:      l.credType,
			UserID:      opts.LinkUserID,
			WorkspaceID: opts.WorkspaceID,
			Detail:      err.Error(),
		})
		return nil, err
	}
	if opts.WorkspaceID != "" {
		if err := l.svc.joinWorkspace(ctx, u.ID, opts.WorkspaceID); err != nil {
			return nil, err
		}
	}
	return u, nil
}

func (l *linker) resolve(ctx context.Context, opts flowLinkOptions) (*db.User, error) {
	enterprise := opts.WorkspaceID != ""
	// vouch runs on every path, so a workspace that loses its domain also
	// loses its existing links.
	vouch := func(u *db.User) (*db.User, error) {
		if !enterprise {
			if err := l.svc.enforceSSO(ctx, u.Email); err != nil {
				return nil, err
			}
			return u, nil
		}
		ok, err := l.svc.managedBy(ctx, opts.WorkspaceID, u.Email)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errIdentityRejected
		}
		return u, nil
	}

	cred, err := l.svc.sys.FindCredentialBySubject(ctx, &db.FindCredentialBySubjectParams{
		Type:     string(l.credType),
		Provider: opts.ProviderID,
		Subject:  opts.Subject,
	})
	if err == nil {
		if opts.LinkUserID != "" && cred.UserID != opts.LinkUserID {
			return nil, errIdentityLinked
		}
		u, err := l.svc.getUserByID(ctx, cred.UserID)
		if err != nil {
			return nil, err
		}
		l.svc.touchCredential(ctx, cred.ID)
		return vouch(u)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	if opts.LinkUserID != "" {
		u, err := l.svc.getUserByID(ctx, opts.LinkUserID)
		if err != nil {
			return nil, err
		}
		if u, err = vouch(u); err != nil {
			return nil, err
		}
		if err := l.link(ctx, opts, u.ID); err != nil {
			return nil, err
		}
		return u, nil
	}

	if opts.Email == "" {
		return nil, errIdentityRejected
	}
	if enterprise {
		ok, err := l.svc.managedBy(ctx, opts.WorkspaceID, opts.Email)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errIdentityRejected
		}
	} else {
		if !opts.EmailVerified {
			return nil, errIdentityRejected
		}
		// Social logins don't satisfy a domain's enforced SSO.
		if err := l.svc.enforceSSO(ctx, opts.Email); err != nil {
			return nil, err
		}
	}

	u, err := l.svc.GetUserByEmail(ctx, opts.Email)
	// An unverified row may be someone else's signup, with their password or
	// passkey on it. The provider proved this address, so that row goes.
	if err == nil && !u.EmailVerified {
		if err = l.svc.sys.DeleteUser(ctx, u.ID); err == nil {
			err = ErrNotFound
		}
	}
	switch {
	case err == nil:
		if enterprise && opts.Name != "" && u.Name != opts.Name {
			if u, err = l.svc.updateUser(ctx, db.UpdateUserParams{ID: u.ID, Name: &opts.Name}); err != nil {
				return nil, err
			}
		}
	case errors.Is(err, ErrNotFound):
		if !opts.JITProvisioning {
			return nil, errIdentityRejected
		}
		if u, err = l.svc.provisionUser(ctx, opts); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}

	// Without the link a later login fails once JIT is off, so leave a trace.
	if err := l.link(ctx, opts, u.ID); err != nil {
		slog.Warn("sso identity link failed", "error", err, "provider", opts.ProviderID, "user_id", u.ID)
	}
	return u, nil
}

// provisionUser marks the email verified since the provider or the domain
// owner already vouched for it.
func (s *Service) provisionUser(ctx context.Context, opts flowLinkOptions) (*db.User, error) {
	var u *db.User
	err := s.conn.WithTx(ctx, func(q *db.Queries) (err error) {
		created, err := q.CreateUser(ctx, &db.CreateUserParams{
			Email: normalizeEmail(opts.Email),
			Name:  opts.Name,
		})
		if err != nil {
			return err
		}
		if err := q.VerifyUserEmail(ctx, created.ID); err != nil {
			return err
		}
		u, err = q.UpdateUser(ctx, &db.UpdateUserParams{ID: created.ID, Picture: nonEmpty(opts.Picture)})
		return err
	})
	if err != nil {
		return nil, mapUserError(err)
	}
	return u, nil
}

func (l *linker) link(ctx context.Context, opts flowLinkOptions, userID string) error {
	_, err := l.svc.sys.UpsertCredential(ctx, &db.UpsertCredentialParams{
		ID:       opts.ProviderID + ":" + opts.Subject,
		UserID:   userID,
		Type:     string(l.credType),
		Provider: opts.ProviderID,
		Subject:  opts.Subject,
		Data:     []byte{},
	})
	if errors.Is(err, pgx.ErrNoRows) || db.IsUniqueViolation(err) {
		return errIdentityLinked
	}
	return err
}

func (s *Service) completeSSO(
	w http.ResponseWriter,
	r *http.Request,
	l *linker,
	returnTo string,
	opts flowLinkOptions,
) {
	ctx := r.Context()
	u, err := l.Resolve(ctx, opts)
	if err != nil {
		// The only trace of a failed workspace join.
		slog.Warn("sso login rejected", "error", err, "provider", opts.ProviderID)
		fail(w, r, "identity rejected")
		return
	}
	cookie, err := s.completeLogin(ctx, u, l.credType)
	if err != nil {
		fail(w, r, "login refused")
		return
	}
	http.SetCookie(w, endFlowBinding())
	http.SetCookie(w, cookie)
	if s.OnUserLogin != nil {
		s.OnUserLogin(w, r, u, l.credType)
	}
	// Re-sanitize, the value round-tripped through the cache.
	returnTo = safeReturnTo(returnTo)
	if returnTo == "" {
		returnTo = "/"
	}
	// 303 so a SAML ACS POST is not replayed against the SPA.
	// #nosec G710 -- safeReturnTo only lets same-origin absolute paths through.
	http.Redirect(w, r, returnTo, http.StatusSeeOther)
}

func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
