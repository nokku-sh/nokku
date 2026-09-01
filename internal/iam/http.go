package iam

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nokku-sh/nokku/internal/db"
)

// SessionCookieName is the cookie the session token is issued in. HttpOnly,
// SameSite Lax, Secure on https, host-only.
const SessionCookieName = "nokku_session"

// maxBodyBytes bounds JSON request bodies.
const maxBodyBytes = 1 << 20

// SessionCookie returns the session cookie for token and expiry.
func (s *Service) SessionCookie(token string, expires time.Time) *http.Cookie {
	return &http.Cookie{ //nolint:gosec // Secure is set dynamically from the base URL scheme
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   s.Secure(),
		SameSite: http.SameSiteLaxMode,
	}
}

// ClearSessionCookie returns the expired empty session cookie.
func (s *Service) ClearSessionCookie() *http.Cookie {
	return &http.Cookie{ //nolint:gosec // Secure is set dynamically from the base URL scheme
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   s.Secure(),
		SameSite: http.SameSiteLaxMode,
	}
}

// Secure reports whether the base URL is https, driving the cookie's Secure
// attribute.
func (s *Service) Secure() bool {
	return strings.HasPrefix(strings.ToLower(s.baseURL), "https://")
}

// SessionTokenFromRequest extracts the session token from the request: the
// cookie first, then an "Authorization: Bearer" header.
func SessionTokenFromRequest(r *http.Request) string {
	if c, err := r.Cookie(SessionCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	const prefix = "Bearer "
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, prefix) {
		return strings.TrimPrefix(h, prefix)
	}
	return ""
}

// AuthenticateRequest resolves token to a principal. User sessions load the
// account so inactive accounts fail closed; device sessions authenticate on
// the session row alone.
func (s *Service) AuthenticateRequest(
	ctx context.Context,
	token string,
) (Principal, db.Session, error) {
	sess, err := s.Sessions.Verify(ctx, token)
	if err != nil {
		return Principal{}, db.Session{}, err
	}
	kind := Kind(sess.Kind)
	p := Principal{ID: sess.SubjectID, Kind: kind, WorkspaceID: deref(sess.WorkspaceID)}
	if kind == KindUser {
		u, err := s.GetUser(ctx, sess.SubjectID)
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

// Middleware attaches the request's principal when a valid session is
// present, and continues either way. Pair with RequireLogin to enforce.
func (s *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token := SessionTokenFromRequest(r); token != "" {
			p, sess, err := s.AuthenticateRequest(r.Context(), token)
			if err == nil {
				ctx := ContextWithPrincipal(r.Context(), p)
				ctx = ContextWithSession(ctx, sess)
				ctx = ContextWithRequestMeta(ctx, RequestMeta{
					Header:     r.Header,
					RemoteAddr: r.RemoteAddr,
				})
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ContextWithSession stores the authenticated session of the request. Both
// the HTTP middleware and the connectrpc interceptor call it, so handlers
// see the same request state on either transport.
func ContextWithSession(ctx context.Context, sess db.Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, sess)
}

// ContextWithRequestMeta stores the transport facts of an authenticated
// request; the audit sink reads them so auth events carry IP and user agent.
func ContextWithRequestMeta(ctx context.Context, meta RequestMeta) context.Context {
	return context.WithValue(ctx, requestMetaKey{}, meta)
}

// RequestMeta carries the transport facts of an authenticated request: the
// audit sink reads them so auth events carry IP and user agent.
type RequestMeta struct {
	Header     http.Header
	RemoteAddr string
}

type requestMetaKey struct{}

// RequestMetaFromContext returns the request metadata and whether it is set.
func RequestMetaFromContext(ctx context.Context) (RequestMeta, bool) {
	m, ok := ctx.Value(requestMetaKey{}).(RequestMeta)
	return m, ok
}

// RequireLogin rejects requests without an authenticated principal.
func (s *Service) RequireLogin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := PrincipalFromContext(r.Context()); !ok {
			WriteError(w, http.StatusUnauthorized, "unauthenticated", "sign in to continue")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireUser rejects principals that are not user sessions: account
// endpoints are a browser surface.
func (s *Service) RequireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p, ok := PrincipalFromContext(r.Context()); ok && p.Kind != KindUser {
			WriteError(
				w,
				http.StatusForbidden,
				"forbidden",
				"account endpoints require a user session",
			)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// CurrentSession returns the authenticated session of the request.
func CurrentSession(ctx context.Context) (db.Session, bool) {
	sess, ok := ctx.Value(sessionKey{}).(db.Session)
	return sess, ok
}

type sessionKey struct{}

// CSRFGuard rejects a state-changing request that presents the session
// cookie from a different origin than the request host. SameSite=Lax cannot
// help against a sibling subdomain, which the browser considers same-site,
// so this check is the second half of the CSRF contract. Requests with
// neither Origin nor Referer pass: browsers send one of the two on every
// POST, and non-browser clients face no CSRF.
func (s *Service) CSRFGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if _, err := r.Cookie(SessionCookieName); err == nil && !sameOrigin(r) {
				WriteError(
					w,
					http.StatusForbidden,
					"invalid_origin",
					"cross-origin request rejected",
				)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// sameOrigin reports whether the request's Origin (or Referer) host matches
// the request host. An absent Origin and Referer counts as same-origin: only
// browsers send these headers, and they send one of the two on every POST.
// The literal "null" origin never passes: sandboxed iframes and data: URLs
// send it while SameSite=Lax still delivers the cookie on same-site POSTs,
// which is exactly a sibling-subdomain attacker's setup.
func sameOrigin(r *http.Request) bool {
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		if strings.EqualFold(origin, "null") {
			return false
		}
		return strings.EqualFold(originHost(origin), r.Host)
	}
	if referer := r.Header.Get("Referer"); referer != "" {
		return strings.EqualFold(originHost(referer), r.Host)
	}
	return true
}

// originHost extracts the host:port from an Origin or Referer header.
func originHost(header string) string {
	u, err := url.Parse(header)
	if err != nil {
		return header
	}
	return u.Host
}

// WriteJSON writes v as a JSON response.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteOK writes an empty 200 JSON object.
func WriteOK(w http.ResponseWriter) {
	WriteJSON(w, http.StatusOK, struct{}{})
}

// WriteError writes the error body the UI parses: {"code": <http status>,
// "message": ...}. The status alone drives the connect code mapping; the
// message carries the human-readable detail.
func WriteError(w http.ResponseWriter, status int, _, msg string) {
	WriteJSON(w, status, map[string]any{"code": status, "message": msg})
}

// ReadJSON decodes the request body into dst.
func ReadJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// CookieToken returns the named cookie's value, or "" when absent.
func CookieToken(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}
