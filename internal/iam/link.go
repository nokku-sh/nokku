package iam

// The identity linker: resolves a verified external identity to a local
// user, creating the linking credential on first sight.

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/db"
)

var (
	ErrIdentityLinked   = errors.New("iam: identity already linked to another account")
	ErrIdentityRejected = errors.New("iam: identity rejected")
)

// flowLinkOptions describes one verified identity.
type flowLinkOptions struct {
	ProviderID string
	// WorkspaceID is the provider's workspace, empty for a global social
	// provider. An enterprise provider only vouches for accounts under its
	// workspace's verified domains. A social provider vouches for nobody,
	// so it needs a provider-verified email to match an account.
	WorkspaceID string
	Subject     string
	Email       string
	// EmailVerified marks the email as verified by the provider.
	EmailVerified bool
	// Name and Picture apply at provision time. Enterprise logins also
	// refresh the name, the IdP owns it.
	Name    string
	Picture string
	// JITProvisioning lets a first-time identity become a user by email.
	JITProvisioning bool
	// LinkUserID attaches the identity to that signed-in user instead of
	// resolving by email.
	LinkUserID string
}

// linker resolves identities of one credential type.
type linker struct {
	svc      *Service
	credType Method
}

// Resolve returns the local user for a verified identity and joins them to
// the provider's workspace. Rejections are recorded as login_denied events.
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
		if err := l.svc.JoinWorkspace(ctx, u.ID, opts.WorkspaceID); err != nil {
			return nil, err
		}
	}
	return u, nil
}

func (l *linker) resolve(ctx context.Context, opts flowLinkOptions) (*db.User, error) {
	enterprise := opts.WorkspaceID != ""
	// vouch rejects accounts an enterprise provider has no authority over.
	// It runs on every path, so a workspace that loses its domain also loses
	// its existing links.
	vouch := func(u *db.User) (*db.User, error) {
		if !enterprise {
			return u, nil
		}
		ok, err := l.svc.managedBy(ctx, opts.WorkspaceID, u.Email)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrIdentityRejected
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
			return nil, ErrIdentityLinked
		}
		u, err := l.svc.GetUserByID(ctx, cred.UserID)
		if err != nil {
			return nil, err
		}
		return vouch(u)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	if opts.LinkUserID != "" {
		u, err := l.svc.GetUserByID(ctx, opts.LinkUserID)
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
		return nil, ErrIdentityRejected
	}
	if enterprise {
		ok, err := l.svc.managedBy(ctx, opts.WorkspaceID, opts.Email)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrIdentityRejected
		}
	} else if !opts.EmailVerified {
		// A social provider's unverified email could claim anyone's account.
		return nil, ErrIdentityRejected
	}

	u, err := l.svc.GetUserByEmail(ctx, opts.Email)
	switch {
	case err == nil:
		if enterprise && opts.Name != "" && u.Name != opts.Name {
			if u, err = l.svc.UpdateUser(ctx, db.UpdateUserParams{ID: u.ID, Name: &opts.Name}); err != nil {
				return nil, err
			}
		}
	case errors.Is(err, ErrNotFound):
		if !opts.JITProvisioning {
			return nil, ErrIdentityRejected
		}
		if u, err = l.svc.provisionUser(ctx, opts); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}

	// The session is valid either way, but without the link a later login
	// fails once JIT is off, so a failure must at least leave a trace.
	if err := l.link(ctx, opts, u.ID); err != nil {
		slog.Warn("sso identity link failed", "error", err, "provider", opts.ProviderID, "user_id", u.ID)
	}
	return u, nil
}

// provisionUser creates a JIT account. Its email is verified: a social
// provider asserted it, or the enterprise workspace owns the domain.
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

// link persists the credential that binds the external subject to the user.
// A subject already bound to someone else fails with ErrIdentityLinked.
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
		return ErrIdentityLinked
	}
	return err
}

// completeSSO resolves the verified identity into a local user, issues a
// session, and redirects to returnTo (default "/").
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
		// Rejections are audited, this log is the only trace of a failed
		// workspace join.
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
	// Re-sanitize at the sink: the value round-tripped through the cache.
	returnTo = safeReturnTo(returnTo)
	if returnTo == "" {
		returnTo = "/"
	}
	// #nosec G710 -- safeReturnTo only lets same-origin absolute paths through.
	http.Redirect(w, r, returnTo, http.StatusTemporaryRedirect)
}

func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
