package iam

// The identity linker: resolves a verified external identity to a local
// user, creating the linking credential on first sight. Ported from kagi's
// flow.go with tenancy flattened to nokku's global users.

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/nokku-sh/nokku/internal/db"
)

// Errors surfaced by the linker.
var (
	ErrIdentityLinked   = errors.New("iam: identity already linked to another account")
	ErrIdentityRejected = errors.New("iam: identity rejected")
)

// flowLinkOptions parameterizes a single Resolve call.
type flowLinkOptions struct {
	ProviderID string
	Subject    string
	// Email, Name, and Picture describe the verified identity. Email drives
	// the domain binding check and find-by-email; Name and Picture only
	// apply at provision time, so a host-set profile is never overwritten.
	Email string
	Name  string
	// Picture is the provider-issued avatar, stored at provision time only.
	Picture string
	// EmailVerified marks the email as verified by the provider; a fresh
	// JIT account inherits it.
	EmailVerified bool
	// Public marks a global social provider (Google, GitHub). Such a
	// provider vouches for nobody, so its identities are only accepted
	// when it asserted the email as verified.
	Public bool
	// JITProvisioning lets a first-time identity become a user by email;
	// without it only linked identities and explicit account links resolve.
	JITProvisioning bool
	// LinkUserID, when non-empty, attaches the identity to that signed-in
	// user (account linking) instead of resolving a new account.
	LinkUserID string
	// Data is the opaque, provider-specific blob stored on a new credential.
	Data []byte
}

// linker resolves identities. OnSSOLogin fires after a successful resolve
// under a workspace-scoped provider so the host can join memberships.
type linker struct {
	svc        *Service
	credType   Method
	OnSSOLogin func(ctx context.Context, userID, workspaceID string) error
}

// Resolve returns the local user for a verified identity: an existing linked
// credential, an explicit link via LinkUserID, or resolution by email
// (domain binding check, JIT provision per the provider's flag).
// Rejections are recorded as login_denied events.
func (l *linker) Resolve(
	ctx context.Context,
	workspaceID string,
	opts flowLinkOptions,
) (*db.User, error) {
	u, err := l.resolve(ctx, opts)
	if err != nil {
		l.svc.record(ctx, Event{
			Action:      ActionLoginDenied,
			Method:      l.credType,
			UserID:      opts.LinkUserID,
			WorkspaceID: workspaceID,
			Detail:      err.Error(),
		})
		return nil, err
	}
	if workspaceID != "" && l.OnSSOLogin != nil {
		if err := l.OnSSOLogin(ctx, u.ID, workspaceID); err != nil {
			return nil, err
		}
	}
	return u, nil
}

func (l *linker) resolve(
	ctx context.Context,
	opts flowLinkOptions,
) (*db.User, error) {
	cred, err := l.svc.q.FindCredentialBySubject(ctx, &db.FindCredentialBySubjectParams{
		Type:     string(l.credType),
		Provider: opts.ProviderID,
		Subject:  opts.Subject,
	})
	if err == nil {
		if opts.LinkUserID != "" && cred.UserID != opts.LinkUserID {
			return nil, ErrIdentityLinked
		}
		return l.svc.GetUser(ctx, cred.UserID)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	if opts.LinkUserID != "" {
		u, uerr := l.svc.GetUser(ctx, opts.LinkUserID)
		if uerr != nil {
			return nil, uerr
		}
		if err := l.Link(ctx, opts.ProviderID, opts.Subject, u.ID, opts.Data); err != nil {
			return nil, err
		}
		return u, nil
	}

	if opts.Email == "" {
		return nil, ErrIdentityRejected
	}
	// A provider with verified domain bindings only accepts identities
	// from those domains; an unbound provider (social login) accepts any.
	bindings, err := l.svc.verifiedDomainsForProvider(ctx, opts.ProviderID)
	if err != nil {
		return nil, err
	}
	if len(bindings) > 0 && !slices.Contains(bindings, emailDomain(opts.Email)) {
		return nil, ErrIdentityRejected
	}
	// The email of an unmatched identity may auto-match a local account
	// only when the provider has verified it, or when the identity comes
	// through a provider the workspace has already vetted via a verified
	// domain binding. Public providers never get the benefit of the
	// doubt: an attacker controlling their profile at a loosely-asserting
	// provider could otherwise claim someone else's email and be signed
	// in as that account.
	if !opts.EmailVerified && (opts.Public || len(bindings) == 0) {
		return nil, ErrIdentityRejected
	}

	u, uerr := l.svc.GetUserByEmail(ctx, opts.Email)
	switch {
	case uerr == nil:
		// Refresh the display name from the IdP; picture is provision-time
		// only so a locally uploaded avatar never regresses.
		if opts.Name != "" && u.Name != opts.Name {
			name := opts.Name
			if u, uerr = l.svc.UpdateUser(ctx, u.ID, UpdateUserPatch{Name: &name}); uerr != nil {
				return nil, uerr
			}
		}
	case errors.Is(uerr, ErrNotFound):
		if !opts.JITProvisioning {
			return nil, ErrIdentityRejected
		}
		if u, uerr = l.svc.provisionUser(ctx, opts); uerr != nil {
			return nil, uerr
		}
	default:
		return nil, uerr
	}

	// Best effort: the store's unique index makes this idempotent. Any
	// other failure still logs: the session is valid but the identity is
	// not persisted, which breaks future logins once JIT provisioning is
	// disabled, with no trace of why.
	if err := l.Link(ctx, opts.ProviderID, opts.Subject, u.ID, opts.Data); err != nil &&
		!isUniqueViolation(err) {
		slog.Warn(
			"sso identity link failed",
			"error", err,
			"provider", opts.ProviderID,
			"user_id", u.ID,
		)
	}
	return u, nil
}

// isUniqueViolation reports whether err is a PostgreSQL unique-constraint
// violation: the expected outcome when a concurrent login linked the same
// identity first.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// provisionUser creates a JIT account from a verified identity.
func (s *Service) provisionUser(ctx context.Context, opts flowLinkOptions) (*db.User, error) {
	u, err := s.q.CreateUser(ctx, &db.CreateUserParams{
		Email: normalizeEmail(opts.Email),
		Name:  opts.Name,
	})
	if err != nil {
		return nil, err
	}
	if opts.EmailVerified {
		_ = s.VerifyUserEmail(ctx, u.ID)
	}
	if opts.Picture != "" {
		pic := opts.Picture
		_, _ = s.UpdateUser(ctx, u.ID, UpdateUserPatch{Picture: &pic})
	}
	return s.GetUser(ctx, u.ID)
}

// verifiedDomainsForProvider lists the verified email domains bound to a
// provider. It runs mid-callback, pre-auth, so the read goes out as
// nokku_system: the provider id already scopes the result.
func (s *Service) verifiedDomainsForProvider(
	ctx context.Context,
	providerID string,
) ([]string, error) {
	var out []string
	err := s.conn.WithTx(ctx, func(q *db.Queries) error {
		rows, err := q.ListVerifiedDomainsForProvider(ctx, providerID)
		if err != nil {
			return err
		}
		out = make([]string, 0, len(rows))
		for _, r := range rows {
			out = append(out, r.Domain)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Link persists the credential that binds the external subject to the user.
func (l *linker) Link(ctx context.Context, providerID, subject, userID string, data []byte) error {
	// Identity flows carry no method-specific blob (only passkeys and
	// passwords do), but the column is NOT NULL: store empty bytes instead
	// of failing the insert and silently dropping the link.
	if data == nil {
		data = []byte{}
	}
	_, err := l.svc.q.UpsertCredential(ctx, &db.UpsertCredentialParams{
		ID:       providerID + ":" + subject,
		UserID:   userID,
		Type:     string(l.credType),
		Provider: providerID,
		Subject:  subject,
		Data:     data,
	})
	return err
}

// completeSSO resolves the verified identity into a local user, issues a
// session, and redirects to the flow's returnTo (default "/"). On a
// rejected identity it writes the error redirect.
func (s *Service) completeSSO(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	l *linker,
	st *flowAuthorizeState,
	opts flowLinkOptions,
	errRedirect string,
) {
	opts.LinkUserID = st.LinkUserID
	u, err := l.Resolve(ctx, st.WorkspaceID, opts)
	if err != nil {
		// The user-facing message is intentionally generic; this log is the
		// only place a membership-join failure (OnSSOLogin) is visible, as
		// resolve rejections are already audited as login_denied.
		slog.Warn("sso login rejected", "error", err, "provider", opts.ProviderID)
		Fail(w, r, errRedirect, "identity rejected")
		return
	}
	// The session stays unpinned: users are global and act per-request in a
	// workspace (the transport resolves the tenant from each request). A pin
	// here would hard-bind the browser session to one workspace and break
	// cross-workspace operations. st.WorkspaceID only drives membership.
	sess, token, err := s.Sessions.Issue(ctx, SessionParams{
		SubjectID: u.ID,
		Kind:      KindUser,
		Method:    l.credType,
		TTL:       s.Sessions.opts.TTL,
	})
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	http.SetCookie(w, endFlowBinding())
	http.SetCookie(w, s.SessionCookie(token, derefTime(sess.ExpiresAt)))
	if s.OnUserLogin != nil {
		s.OnUserLogin(w, r, u, l.credType)
	}
	// Re-sanitize at the sink: the state round-tripped through the cache,
	// and the redirect target must be same-origin regardless of what wrote
	// the state.
	returnTo := SafeReturnTo(st.ReturnTo)
	if returnTo == "" {
		returnTo = "/"
	}
	// #nosec G710 -- returnTo passes SafeReturnTo at flow start and again here, so only same-origin absolute paths reach the redirect.
	http.Redirect(w, r, returnTo, http.StatusTemporaryRedirect)
}
