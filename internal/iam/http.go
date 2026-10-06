package iam

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/db"
)

const (
	sessionTTL        = 168 * time.Hour
	sessionCookieName = "nokku_session"
	signupCookieName  = "nokku_signup"
)

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

func (s *Service) ClearSessionCookie() *http.Cookie {
	return s.newCookie(sessionCookieName, "", time.Unix(0, 0))
}

// SignupCookie marks the browser an account was created in. The mailed
// verify link only works there, see ConsumeVerifyToken.
func (s *Service) SignupCookie(userID string) *http.Cookie {
	return s.newCookie(signupCookieName, s.signupMAC(userID), s.now().Add(unverifiedUserTTL))
}

func (s *Service) signupMAC(userID string) string {
	mac := hmac.New(sha256.New, s.signupKey)
	mac.Write([]byte(userID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func sessionFromCookie(h http.Header) string {
	return cookieFromHeader(h, sessionCookieName)
}

// cookieFromHeader exists because connect only exposes headers, not an [http.Request].
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

// Middleware attaches a cookie session's principal and continues either way.
// Header tokens belong to connect, which also checks their DPoP binding.
func (s *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, sess, err := s.AuthenticateToken(r.Context(), sessionFromCookie(r.Header))
		if err != nil || p.Kind != actor.KindUser {
			next.ServeHTTP(w, r)
			return
		}
		ctx := actor.ContextWithPrincipal(r.Context(), p)
		ctx = ContextWithSession(ctx, sess)
		ctx = ContextWithRequestMeta(ctx, RequestMeta{Header: r.Header, RemoteAddr: r.RemoteAddr})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func ContextWithSession(ctx context.Context, sess db.Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, sess)
}

func ContextWithRequestMeta(ctx context.Context, meta RequestMeta) context.Context {
	return context.WithValue(ctx, requestMetaKey{}, meta)
}

// RequestMeta gives audit events their IP and user agent.
type RequestMeta struct {
	Header     http.Header
	RemoteAddr string
}

type requestMetaKey struct{}

func RequestMetaFromContext(ctx context.Context) (RequestMeta, bool) {
	m, ok := ctx.Value(requestMetaKey{}).(RequestMeta)
	return m, ok
}

func (s *Service) RequireLogin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := actor.PrincipalFromContext(r.Context()); !ok {
			writeError(w, http.StatusUnauthorized, "sign in to continue")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func CurrentSession(ctx context.Context) (db.Session, bool) {
	sess, ok := ctx.Value(sessionKey{}).(db.Session)
	return sess, ok
}

type sessionKey struct{}

func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

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
