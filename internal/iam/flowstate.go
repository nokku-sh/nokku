package iam

// Cross-request flow state and shared SSO plumbing, ported from kagi's
// flow.go / flow_oauth.go / claims.go / util.go.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nokku-sh/nokku/internal/cache"
	"github.com/nokku-sh/nokku/internal/crypto"
)

// Cache is the shared cache contract, aliased from internal/cache so the
// flow files read naturally.
type Cache = cache.Cache

// flowStateTTL bounds how long an in-flight SSO login state stays valid.
const flowStateTTL = 10 * time.Minute

// flowCookieName identifies the browser that started an SSO flow. The
// callback is only honored in that browser, which blocks login CSRF: an
// attacker completing the IdP leg themselves cannot donate the resulting
// callback URL to a signed-in victim to swap their session.
const flowCookieName = "nokku_flow"

// startFlowBinding sets the flow cookie and returns its value for the flow
// state to carry. For SAML the callback arrives as a cross-site IdP form
// POST, which SameSite=Lax cookies do not accompany, so those flows need a
// None cookie (Secure, and therefore only when the app is served over
// HTTPS); pass none=true there. A crypto failure returns "" and the
// binding degrades to allowing the callback: availability over
// strictness on a defense-in-depth control.
func startFlowBinding(w http.ResponseWriter, none bool) string {
	v, err := crypto.RandomString(32)
	if err != nil {
		return ""
	}
	c := &http.Cookie{
		Name:     flowCookieName,
		Value:    v,
		Path:     "/",
		MaxAge:   int(flowStateTTL.Seconds()),
		HttpOnly: true,
	}
	if none {
		c.SameSite = http.SameSiteNoneMode
		c.Secure = true
	} else {
		c.SameSite = http.SameSiteLaxMode
	}
	http.SetCookie(w, c)
	return v
}

// checkFlowBinding reports whether the callback browser matches the one the
// flow was started in. An empty recorded value (binding was not set) allows.
func checkFlowBinding(r *http.Request, expected string) bool {
	if expected == "" {
		return true
	}
	c, err := r.Cookie(flowCookieName)
	return err == nil && c.Value == expected
}

// endFlowBinding clears the flow cookie after the flow resolved. Browsers
// match the deletion by name, path, and domain, so a Secure attribute is
// unnecessary on the clearing cookie; Lax keeps the Set-Cookie acceptable
// over plain HTTP.
func endFlowBinding() *http.Cookie {
	return &http.Cookie{ //nolint:gosec // Secure is not needed to match a cookie for deletion
		Name:     flowCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// crossSiteNavigation reports whether the browser marked the request as a
// cross-site navigation. SSO login GETs attach the signed-in user for
// account linking, and top-level cross-site navigations carry the
// SameSite=Lax session cookie past the CSRF guard (which inspects POSTs
// only), so linking must not start from a link on another site.
func crossSiteNavigation(r *http.Request) bool {
	return r.Header.Get("Sec-Fetch-Site") == "cross-site"
}

// linkUserIDFor returns the signed-in user to link the SSO identity to, or
// "" when the login started as a cross-site navigation (no linking).
func linkUserIDFor(ctx context.Context, r *http.Request) string {
	if crossSiteNavigation(r) {
		return ""
	}
	return SubjectFromContext(ctx)
}

// providerHTTPTimeout bounds every outbound call to an identity provider.
const providerHTTPTimeout = 15 * time.Second

// providerCacheTTL bounds how long discovered provider endpoints and parsed
// IdP metadata stay cached in memory.
const providerCacheTTL = 10 * time.Minute

// ErrSSORequired is returned when a login method is refused because the
// account's email domain enforces SSO. The transport maps it to 428.
var ErrSSORequired = errors.New("iam: single sign-on is required for this account")

// state carries a typed payload between requests in a cache, under a
// package-specific key prefix. Take reads and deletes in one atomic step, so
// the state is single-use even when consumers race.
type state[T any] struct {
	cache  Cache
	prefix string
	ttl    time.Duration
}

func newState[T any](c Cache, prefix string, ttl time.Duration) *state[T] {
	return &state[T]{cache: c, prefix: prefix, ttl: ttl}
}

func (s *state[T]) Put(ctx context.Context, key string, v T) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.cache.Set(ctx, s.prefix+key, b, s.ttl)
}

func (s *state[T]) Get(ctx context.Context, key string) (T, error) {
	var v T
	if key == "" {
		return v, errors.New("missing state")
	}
	b, err := s.cache.Get(ctx, s.prefix+key)
	if err != nil {
		return v, err
	}
	return v, json.Unmarshal(b, &v)
}

func (s *state[T]) Take(ctx context.Context, key string) (T, error) {
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

// claimString returns the first non-empty string value among the named keys,

// claimString returns the first non-empty string value among the named keys,
// stringifying numeric claims (OIDC subjects, GitHub's numeric "id").
func claimString(m map[string]any, keys ...string) string {
	for _, key := range keys {
		if key == "" {
			continue
		}
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

// claimBool returns the first boolean among the named keys, accepting the
// string forms "true" and "1".
func claimBool(m map[string]any, keys ...string) bool {
	for _, key := range keys {
		if key == "" {
			continue
		}
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

// attrValue returns the first value among the named SAML attribute names.
func attrValue(attrs map[string][]string, names ...string) string {
	for _, name := range names {
		if name == "" {
			continue
		}
		if v := attrs[name]; len(v) > 0 && v[0] != "" {
			return v[0]
		}
	}
	return ""
}

// SafeReturnTo rejects open redirects: only same-origin absolute paths
// survive, no protocol-relative or backslash forms, no CR/LF.
func SafeReturnTo(p string) string {
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") ||
		strings.HasPrefix(p, "/\\") || strings.Contains(p, "\r") ||
		strings.Contains(p, "\n") {
		return ""
	}
	return p
}

// Fail writes a failure response: a redirect when errRedirect is non-empty,
// otherwise a 401 body. The error parameter is appended without disturbing
// any query string the redirect already carries.
func Fail(w http.ResponseWriter, r *http.Request, errRedirect, msg string) {
	if errRedirect != "" {
		sep := "?"
		if strings.Contains(errRedirect, "?") {
			sep = "&"
		}
		http.Redirect(
			w,
			r,
			errRedirect+sep+"error="+url.QueryEscape(msg),
			http.StatusTemporaryRedirect,
		)
		return
	}
	WriteError(w, http.StatusUnauthorized, msg)
}

func emailDomain(email string) string {
	_, domain, ok := strings.Cut(email, "@")
	if !ok {
		return ""
	}
	return strings.ToLower(domain)
}
