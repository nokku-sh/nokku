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

	"github.com/nokku-sh/nokku/core/internal/crypto"
)

const (
	flowStateTTL = 10 * time.Minute
	// Only the browser that started the flow has it, so no login CSRF.
	flowCookieName = "nokku_flow"
	// Browsers drop a cookie past 4096 bytes, name and attributes included.
	maxFlowCookie = 3800
	// A longer return path would not fit the cookie next to the rest.
	maxReturnTo = 1024
	// One marker per finished flow in the last flowStateTTL.
	spentFlowEntries    = 10_000
	ssoErrorPath        = "/sso-error"
	providerHTTPTimeout = 15 * time.Second
	providerCacheTTL    = 10 * time.Minute
	// One provider per issuer, each hosted workspace may bring its own.
	providerCacheEntries = 10_000
)

var errFlowState = errors.New("iam: invalid or expired flow state")

// sealed keeps flow state in an encrypted cookie, starting one stores nothing.
type sealed[T any] struct {
	svc    *Service
	cookie string
	// use is bound into the seal, so one flow's state never opens as another's.
	use string
	ttl time.Duration
}

type envelope[T any] struct {
	ID      string `json:"id"`
	Expires int64  `json:"exp"`
	State   T      `json:"state"`
}

// providerContext is how oauth2 and go-oidc pick up the guarded client.
func (s *Service) providerContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, s.idp)
}

// put returns the id that travels through the provider and back.
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

// take refuses another flow's state, an expired one, and one already spent.
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

// safeReturnTo only passes same-origin paths. Browsers drop tabs and newlines,
// which turns "/\t/host" into "//host".
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
