package iam

import (
	"context"
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
	// sessionSeenEvery is how exact "last active" in the sessions list is.
	// A busy session must not turn every request into a write.
	sessionSeenEvery = time.Minute
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
		p, tok, err := s.AuthenticateToken(r.Context(), sessionFromCookie(r.Header))
		if err != nil || p.Kind != actor.KindUser {
			next.ServeHTTP(w, r)
			return
		}
		s.noteSeen(r.Context(), tok)
		ctx := actor.ContextWithPrincipal(r.Context(), p)
		ctx = ContextWithToken(ctx, tok)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func ContextWithToken(ctx context.Context, tok db.AccessToken) context.Context {
	return context.WithValue(ctx, tokenKey{}, tok)
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

// CurrentToken is the credential the request authenticated with.
func CurrentToken(ctx context.Context) (db.AccessToken, bool) {
	tok, ok := ctx.Value(tokenKey{}).(db.AccessToken)
	return tok, ok
}

type tokenKey struct{}

func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	WriteJSON(w, status, map[string]any{"code": status, "message": msg})
}

func deref[T any](p *T) (v T) {
	if p != nil {
		v = *p
	}
	return v
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
