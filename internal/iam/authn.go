package iam

// Transport credential resolution. One decision tree, in one place:
//
//   session cookie                    → user session (browser)
//   Authorization: Bearer nokku_sa_…  → service-account API key (no session)
//   Authorization: Bearer <token>     → session token (device cookies rejected)
//   Authorization: DPoP <token>       → key-bound session (CLI, daemon)
//
// Key-bound sessions (CLI device logins, daemons) must present a DPoP proof
// signed by the session's bound key on every request (RFC 9449).

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
)

// APIKeyPrefix marks service-account bearer credentials. The remainder is
// the raw secret; only its hash is stored.
const APIKeyPrefix = "nokku_sa_" //nolint:gosec // a token scheme prefix, not a credential

// Authenticate resolves a connect request credential into a principal and
// the session row behind it (empty for service accounts, which have no
// session). The caller injects both into the request context.
func (s *Service) Authenticate(
	ctx context.Context,
	header http.Header,
	procedure string,
) (Principal, db.Session, error) {
	token, fromHeader := requestCredential(header)
	if strings.HasPrefix(token, APIKeyPrefix) {
		p, err := s.AuthenticateAPIKey(ctx, token)
		return p, db.Session{}, err
	}

	// An empty token falls through to VerifySession, which answers
	// ErrNoSession like any unknown credential.
	p, sess, err := s.AuthenticateToken(ctx, token)
	if err != nil {
		return Principal{}, db.Session{}, err
	}
	// The remembered-device cookie is a device handle, not an API
	// credential: it only ever rides the cookie path, so a header
	// presentation means a leaked cookie being replayed. Accepting it
	// would turn a 24-hour session leak into a 180-day one.
	if fromHeader && p.Kind == KindWebDevice {
		return Principal{}, db.Session{}, errors.New("device credentials are not API tokens")
	}
	if sess.Binding != "" {
		if err := s.verifySessionProof(ctx, header, procedure, token, sess.Binding); err != nil {
			return Principal{}, db.Session{}, err
		}
	}
	return p, sess, nil
}

// AuthenticateToken resolves a session token to a principal. User sessions
// load the account so inactive accounts fail closed; device sessions
// authenticate on the session row alone.
func (s *Service) AuthenticateToken(
	ctx context.Context,
	token string,
) (Principal, db.Session, error) {
	sess, err := s.VerifySession(ctx, token)
	if err != nil {
		return Principal{}, db.Session{}, err
	}
	kind := Kind(sess.Kind)
	p := Principal{ID: sess.SubjectID, Kind: kind, WorkspaceID: deref(sess.WorkspaceID)}
	if kind == KindUser {
		u, err := s.GetUserByID(ctx, sess.SubjectID)
		if err != nil {
			return Principal{}, db.Session{}, err
		}
		if !u.Active {
			return Principal{}, db.Session{}, ErrInactive
		}
		p.Email = u.Email
	}
	return p, sess, nil
}

// AuthenticateAPIKey resolves a service-account bearer credential. The
// lookup runs on the admin pool: it is the step that establishes the
// tenant, so it cannot be tenant-scoped (RLS) itself.
func (s *Service) AuthenticateAPIKey(ctx context.Context, raw string) (Principal, error) {
	hash, err := crypto.HashToken(raw)
	if err != nil {
		return Principal{}, err
	}
	sa, err := s.conn.AdminQuerier().GetServiceAccountByTokenHash(ctx, &hash)
	if err != nil {
		return Principal{}, ErrInvalidCredentials
	}
	if sa.ExpiresAt != nil && sa.ExpiresAt.Before(s.now()) {
		return Principal{}, ErrCredentialsExpired
	}
	return Principal{
		ID:          sa.ID,
		Kind:        KindServiceAccount,
		WorkspaceID: sa.WorkspaceID,
	}, nil
}

// NewAPIKey mints a service-account credential: the secret with the API key
// prefix, and the hash of the full credential. The raw value must be
// delivered to the caller exactly once; only its hash is stored.
func NewAPIKey() (raw string, hash crypto.HashedToken, err error) {
	secret, _, err := crypto.NewSecret()
	if err != nil {
		return "", "", err
	}
	raw = APIKeyPrefix + secret
	hash, err = crypto.HashToken(raw)
	if err != nil {
		return "", "", err
	}
	return raw, hash, nil
}

// verifySessionProof checks the DPoP proof that must accompany every
// request made with a key-bound session: a fresh signature by the session's
// bound key over this procedure, carrying the hash of the token itself
// (RFC 9449 section 7.1). Cookie sessions carry no binding and skip the
// check.
func (s *Service) verifySessionProof(
	ctx context.Context,
	header http.Header,
	procedure, token, binding string,
) error {
	if s.DPoP == nil {
		return errors.New("iam: dpop is not configured")
	}
	proof := header.Get("DPoP")
	if proof == "" {
		return ErrDPoPRequired
	}
	return s.DPoP.VerifySession(ctx, proof, token, http.MethodPost, s.baseURL+procedure, binding)
}

// AdvertiseDPoPNonce writes the current DPoP nonce, alongside the canonical
// API URL, to a response header so a client recovering from a stale nonce
// also corrects the htu it signs (RFC 9449 section 8).
func (s *Service) AdvertiseDPoPNonce(h http.Header) {
	if s.DPoP == nil {
		return
	}
	h.Set(DeviceURLHeader, s.baseURL)
	h.Set("DPoP-Nonce", s.DPoP.CurrentNonce())
}

// requestCredential extracts the request credential and reports whether it
// came from the Authorization header (as opposed to the session cookie).
// Both the "Bearer" and "DPoP" schemes are accepted: DPoP-bound clients
// (CLI and daemons) MUST use the DPoP scheme for their bound tokens
// (RFC 9449).
func requestCredential(h http.Header) (token string, fromHeader bool) {
	if a := h.Get("Authorization"); a != "" {
		// Schemes are case-insensitive (RFC 9110 section 11.1).
		for _, scheme := range []string{"bearer ", "dpop "} {
			if len(a) >= len(scheme) && strings.EqualFold(a[:len(scheme)], scheme) {
				return strings.TrimSpace(a[len(scheme):]), true
			}
		}
	}
	// The session cookie doubles as the browser credential for connect
	// calls made with credentials: include.
	if c := CookieFromHeader(h, sessionCookieName); c != "" {
		return c, false
	}
	return "", false
}

// derefTime tolerates a nil expiry.
func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}
