package iam

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/cache"
	"github.com/nokku-sh/nokku/internal/crypto"
)

const (
	flowStateTTL = 10 * time.Minute
	// flowCookieName binds the callback to the browser that started the flow,
	// which blocks login CSRF.
	flowCookieName      = "nokku_flow"
	ssoErrorPath        = "/sso-error"
	providerHTTPTimeout = 15 * time.Second
	providerCacheTTL    = 10 * time.Minute
)

var ErrSSORequired = errors.New("iam: single sign-on is required for this account")

// providerContext is how oauth2 and go-oidc pick up the guarded client.
func (s *Service) providerContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, s.idp)
}

// startFlowBinding takes none=true for SAML, whose cross-site POST callback
// Lax cookies don't accompany. SameSite=None requires HTTPS.
func startFlowBinding(w http.ResponseWriter, none bool) (string, error) {
	v, err := crypto.RandomString(32)
	if err != nil {
		return "", err
	}
	c := &http.Cookie{
		Name:     flowCookieName,
		Value:    v,
		Path:     "/",
		MaxAge:   int(flowStateTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if none {
		c.SameSite = http.SameSiteNoneMode
		c.Secure = true
	}
	http.SetCookie(w, c)
	return v, nil
}

func checkFlowBinding(r *http.Request, expected string) bool {
	c, err := r.Cookie(flowCookieName)
	return err == nil && expected != "" && c.Value == expected
}

func endFlowBinding() *http.Cookie {
	return &http.Cookie{ //nolint:gosec // Secure is not needed to match a cookie for deletion
		Name:     flowCookieName,
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// linkUserIDFor never links on cross-site navigations, which carry the Lax
// session cookie past the CSRF guard.
func linkUserIDFor(ctx context.Context, r *http.Request) string {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return ""
	}
	return actor.SubjectFromContext(ctx)
}

// state is single-use, Take reads and deletes atomically.
type state[T any] struct {
	cache  cache.Cache
	prefix string
	ttl    time.Duration
}

func newState[T any](c cache.Cache, prefix string, ttl time.Duration) *state[T] {
	return &state[T]{cache: c, prefix: prefix, ttl: ttl}
}

func (s *state[T]) put(ctx context.Context, v T) (string, error) {
	key, err := crypto.RandomString(32)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return key, s.cache.Set(ctx, s.prefix+key, b, s.ttl)
}

func (s *state[T]) take(ctx context.Context, key string) (T, error) {
	var v T
	if key == "" {
		return v, errors.New("missing state")
	}
	b, err := s.cache.GetDel(ctx, s.prefix+key)
	if err != nil {
		return v, err
	}
	return v, json.Unmarshal(b, &v)
}

// claimString also stringifies numeric claims like GitHub's "id".
func claimString(m map[string]any, keys ...string) string {
	for _, key := range keys {
		switch v := m[key].(type) {
		case string:
			if v != "" {
				return v
			}
		case json.Number:
			return v.String()
		case float64:
			return strconv.FormatFloat(v, 'f', -1, 64)
		}
	}
	return ""
}

func claimBool(m map[string]any, keys ...string) bool {
	for _, key := range keys {
		switch v := m[key].(type) {
		case bool:
			return v
		case string:
			if strings.EqualFold(v, "true") || v == "1" {
				return true
			}
		}
	}
	return false
}

func attrValue(attrs map[string][]string, names ...string) string {
	for _, name := range names {
		if v := attrs[name]; len(v) > 0 && v[0] != "" {
			return v[0]
		}
	}
	return ""
}

// safeReturnTo only lets same-origin absolute paths through.
func safeReturnTo(p string) string {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") ||
		strings.HasPrefix(p, "/\\") || strings.ContainsAny(p, "\r\n") {
		return ""
	}
	return p
}

func fail(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, ssoErrorPath+"?error="+url.QueryEscape(msg), http.StatusSeeOther)
}

func emailDomain(email string) string {
	_, domain, ok := strings.Cut(email, "@")
	if !ok {
		return ""
	}
	return strings.ToLower(domain)
}
