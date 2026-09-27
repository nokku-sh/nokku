package iam

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nokku-sh/nokku/internal/db"
)

const (
	sessionTTL        = 168 * time.Hour
	sessionCookieName = "nokku_session"
)

// newCookie builds a host-only, HttpOnly, Lax cookie with the service's
// Secure attribute; every browser cookie of the service shares these.
func (s *Service) newCookie(name, value string, expires time.Time) *http.Cookie {
	return &http.Cookie{ //nolint:gosec // Secure is set dynamically from the base URL scheme
		Name:     name,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
	}
}

// ClearSessionCookie returns the expired empty session cookie.
func (s *Service) ClearSessionCookie() *http.Cookie {
	return s.newCookie(sessionCookieName, "", time.Unix(0, 0))
}

// sessionFromCookie returns the browser session token, or "".
func sessionFromCookie(h http.Header) string {
	return cookieFromHeader(h, sessionCookieName)
}

// cookieFromHeader returns the value of the named cookie in the request
// header map, or "". The net/http cookie parser only speaks [http.Request],
// so the connect surface (request headers only) shares this.
func cookieFromHeader(h http.Header, name string) string {
	for _, line := range h.Values("Cookie") {
		for pair := range strings.SplitSeq(line, ";") {
			n, v, _ := strings.Cut(pair, "=")
			if strings.TrimSpace(n) != name {
				continue
			}
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return ""
}

// Middleware attaches the principal of a browser session cookie, and
// continues either way. Pair with RequireLogin to enforce. Only user cookie
// sessions count here: header tokens belong to the connect surface, which
// also checks their DPoP binding.
func (s *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, sess, err := s.AuthenticateToken(r.Context(), sessionFromCookie(r.Header))
		if err != nil || p.Kind != KindUser {
			next.ServeHTTP(w, r)
			return
		}
		ctx := ContextWithPrincipal(r.Context(), p)
		ctx = ContextWithSession(ctx, sess)
		ctx = ContextWithRequestMeta(ctx, RequestMeta{Header: r.Header, RemoteAddr: r.RemoteAddr})
		next.ServeHTTP(w, r.WithContext(ctx))
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
			writeError(w, http.StatusUnauthorized, "sign in to continue")
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
			if _, err := r.Cookie(sessionCookieName); err == nil && !sameOrigin(r) {
				writeError(w, http.StatusForbidden, "cross-origin request rejected")
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

// WriteError writes the error body the UI parses: {"code": <http status>,
// "message": ...}. The status alone drives the connect code mapping; the
// message carries the human-readable detail.
func writeError(w http.ResponseWriter, status int, msg string) {
	WriteJSON(w, status, map[string]any{"code": status, "message": msg})
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func deviceNameFromUA(ua string) string {
	if ua == "" {
		return "Unknown device"
	}

	browser := "Unknown browser"
	switch {
	case strings.Contains(ua, "Edg/"):
		browser = "Edge"
	case strings.Contains(ua, "OPR/") || strings.Contains(ua, "Opera"):
		browser = "Opera"
	case strings.Contains(ua, "Firefox/"):
		browser = "Firefox"
	case strings.Contains(ua, "Chrome/"):
		browser = "Chrome"
	case strings.Contains(ua, "Safari/"):
		browser = "Safari"
	}

	os := "unknown OS"
	switch {
	case strings.Contains(ua, "Windows"):
		os = "Windows"
	case strings.Contains(ua, "Android"):
		os = "Android"
	case strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad"):
		os = "iOS"
	case strings.Contains(ua, "Mac OS X"):
		os = "macOS"
	case strings.Contains(ua, "CrOS"):
		os = "ChromeOS"
	case strings.Contains(ua, "Linux"):
		os = "Linux"
	}

	return browser + " on " + os
}
