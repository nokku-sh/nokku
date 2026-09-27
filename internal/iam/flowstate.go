package iam

// Cross-request flow state and shared SSO plumbing.

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/oauth2"

	"github.com/nokku-sh/nokku/internal/cache"
	"github.com/nokku-sh/nokku/internal/crypto"
)

// Cache is the shared cache contract.
type Cache = cache.Cache

const (
	// flowStateTTL bounds how long an in-flight SSO login stays valid.
	flowStateTTL = 10 * time.Minute
	// flowCookieName identifies the browser that started an SSO flow. The
	// callback is only honored there, which blocks login CSRF: an attacker
	// cannot donate their own callback URL to a signed-in victim.
	flowCookieName = "nokku_flow"
	ssoErrorPath   = "/sso-error"
	// providerHTTPTimeout bounds every outbound call to an identity provider.
	providerHTTPTimeout = 15 * time.Second
	// providerCacheTTL bounds how long discovered endpoints and parsed IdP
	// metadata stay cached.
	providerCacheTTL = 10 * time.Minute
)

// ErrSSORequired is returned when a login method is refused because the
// account's email domain enforces SSO.
var ErrSSORequired = errors.New("iam: single sign-on is required for this account")

// cgnat is the carrier-grade NAT range, internal on most clouds.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// newProviderClient returns the HTTP client for IdP endpoints. Workspace
// admins choose those URLs, so unless allowPrivate is set the client refuses
// to connect anywhere but the public internet. The check runs on the dialed
// address, so DNS rebinding cannot slip past it.
func newProviderClient(allowPrivate bool) *http.Client {
	dialer := &net.Dialer{Timeout: providerHTTPTimeout}
	if !allowPrivate {
		dialer.Control = func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return err
			}
			ip := ap.Addr().Unmap()
			if !ip.IsGlobalUnicast() || ip.IsPrivate() || cgnat.Contains(ip) {
				return errors.New("iam: identity provider address is not public")
			}
			return nil
		}
	}
	transport := &http.Transport{
		DialContext:         dialer.DialContext,
		TLSHandshakeTimeout: providerHTTPTimeout,
		ForceAttemptHTTP2:   true,
	}
	return &http.Client{Timeout: providerHTTPTimeout, Transport: transport}
}

// providerContext carries the guarded client into the oauth2 and go-oidc
// calls, which read it from the context.
func (s *Service) providerContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, s.idp)
}

// startFlowBinding sets the flow cookie and returns its value for the flow
// state to carry. SAML callbacks arrive as a cross-site POST that Lax
// cookies do not accompany, so those flows pass none=true for a
// SameSite=None cookie, which browsers only keep over HTTPS.
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

// checkFlowBinding reports whether the callback browser is the one the flow
// started in.
func checkFlowBinding(r *http.Request, expected string) bool {
	c, err := r.Cookie(flowCookieName)
	return err == nil && expected != "" && c.Value == expected
}

// endFlowBinding clears the flow cookie. Browsers match a deletion by name,
// path, and domain, so it needs no Secure attribute.
func endFlowBinding() *http.Cookie {
	return &http.Cookie{ //nolint:gosec // Secure is not needed to match a cookie for deletion
		Name:     flowCookieName,
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// linkUserIDFor returns the signed-in user to link the SSO identity to. A
// login started as a cross-site navigation carries the Lax session cookie
// past the CSRF guard, so it never links.
func linkUserIDFor(ctx context.Context, r *http.Request) string {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return ""
	}
	return SubjectFromContext(ctx)
}

// state carries a typed payload between requests under a key prefix. Take
// reads and deletes in one atomic step, so a state is single-use.
type state[T any] struct {
	cache  Cache
	prefix string
	ttl    time.Duration
}

func newState[T any](c Cache, prefix string, ttl time.Duration) *state[T] {
	return &state[T]{cache: c, prefix: prefix, ttl: ttl}
}

// Put stores v under a fresh random key and returns the key.
func (s *state[T]) Put(ctx context.Context, v T) (string, error) {
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
// stringifying numeric claims (OIDC subjects, GitHub's numeric "id").
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

// claimBool returns the first boolean among the named keys, accepting the
// string forms "true" and "1".
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

// attrValue returns the first value among the named SAML attribute names.
func attrValue(attrs map[string][]string, names ...string) string {
	for _, name := range names {
		if v := attrs[name]; len(v) > 0 && v[0] != "" {
			return v[0]
		}
	}
	return ""
}

// safeReturnTo rejects open redirects: only same-origin absolute paths
// survive, no protocol-relative or backslash forms, no CR/LF.
func safeReturnTo(p string) string {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") ||
		strings.HasPrefix(p, "/\\") || strings.ContainsAny(p, "\r\n") {
		return ""
	}
	return p
}

// fail redirects to the SSO error page with msg.
func fail(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, ssoErrorPath+"?error="+url.QueryEscape(msg), http.StatusTemporaryRedirect)
}

func emailDomain(email string) string {
	_, domain, ok := strings.Cut(email, "@")
	if !ok {
		return ""
	}
	return strings.ToLower(domain)
}
