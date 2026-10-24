package iam

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/oauth2"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/crypto"
)

const (
	flowStateTTL = 10 * time.Minute
	// flowCookieName holds the state of an SSO login. Only the browser that started the flow has it, so no login CSRF.
	flowCookieName = "nokku_flow"
	// Browsers drop a cookie past 4096 bytes, name and attributes included.
	maxFlowCookie = 3800
	// A longer return path would not fit the cookie next to the rest.
	maxReturnTo = 1024
	// One marker per login in the last flowStateTTL.
	spentFlowEntries    = 10_000
	ssoErrorPath        = "/sso-error"
	providerHTTPTimeout = 15 * time.Second
	providerCacheTTL    = 10 * time.Minute
	// One discovered provider per issuer, every workspace on the hosted service may bring its own.
	providerCacheEntries = 10_000
)

var (
	errFlowState   = errors.New("iam: invalid or expired flow state")
	errLinkRefused = errors.New("iam: linking needs a session and a same-origin request")
)

// providerContext is how oauth2 and go-oidc pick up the guarded client.
func (s *Service) providerContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, s.idp)
}

// linkUserIDFor only links for the profile page's own request. The Lax session cookie rides on any navigation.
func linkUserIDFor(ctx context.Context, r *http.Request) (string, error) {
	if r.URL.Query().Get("link") != "true" {
		return "", nil
	}
	userID := actor.SubjectFromContext(ctx)
	if userID == "" || r.Header.Get("Sec-Fetch-Site") != "same-origin" {
		return "", errLinkRefused
	}
	return userID, nil
}

// sealed keeps the state of a browser flow in an encrypted cookie, so starting a flow stores nothing on the server.
type sealed[T any] struct {
	svc    *Service
	cookie string
	// use is bound into the seal, so the state of one flow never opens as another's.
	use string
	ttl time.Duration
}

type envelope[T any] struct {
	ID      string `json:"id"`
	Expires int64  `json:"exp"`
	State   T      `json:"state"`
}

// put seals v into the cookie. The returned id is for the value that travels through the provider and back.
func (s *sealed[T]) put(w http.ResponseWriter, v T) (string, error) {
	id := crypto.RandomString(32)
	expires := s.svc.now().Add(s.ttl)
	plain, err := json.Marshal(envelope[T]{ID: id, Expires: expires.Unix(), State: v})
	if err != nil {
		return "", err
	}
	nonce := make([]byte, s.svc.flowAEAD.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	value := base64.RawURLEncoding.EncodeToString(s.svc.flowAEAD.Seal(nonce, nonce, plain, []byte(s.use)))
	if len(value) > maxFlowCookie {
		return "", errors.New("iam: flow state does not fit a cookie")
	}
	http.SetCookie(w, s.svc.newCookie(s.cookie, value, expires))
	return id, nil
}

// take refuses a state of another flow, an expired one, and one whose flow already ended in a login.
func (s *sealed[T]) take(r *http.Request) (T, string, error) {
	var e envelope[T]
	raw, err := base64.RawURLEncoding.DecodeString(s.svc.cookieValue(r.Header, s.cookie))
	n := s.svc.flowAEAD.NonceSize()
	if err != nil || len(raw) <= n {
		return e.State, "", errFlowState
	}
	plain, err := s.svc.flowAEAD.Open(nil, raw[:n], raw[n:], []byte(s.use))
	if err != nil || json.Unmarshal(plain, &e) != nil {
		return e.State, "", errFlowState
	}
	if s.svc.now().Unix() >= e.Expires {
		return e.State, "", errFlowState
	}
	if _, spent := s.svc.spent.Get(e.ID); spent {
		return e.State, "", errFlowState
	}
	return e.State, e.ID, nil
}

// spendFlow makes a finished flow single use.
func (s *Service) spendFlow(id string) {
	s.spent.Set(id, struct{}{})
}

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

// claimIsFalse also takes the string some providers send for a boolean.
func claimIsFalse(v any) bool {
	switch v := v.(type) {
	case bool:
		return !v
	case string:
		return strings.EqualFold(v, "false")
	}
	return false
}

func claimIsTrue(v any) bool {
	switch v := v.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	}
	return false
}

// safeReturnTo only lets same-origin absolute paths through. Browsers drop tabs and newlines, which turns "/\t/host" into "//host".
func safeReturnTo(p string) string {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || len(p) > maxReturnTo ||
		strings.HasPrefix(p, "/\\") || strings.ContainsFunc(p, unicode.IsControl) {
		return ""
	}
	return p
}

func fail(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, ssoErrorPath+"?error="+url.QueryEscape(msg), http.StatusSeeOther)
}
