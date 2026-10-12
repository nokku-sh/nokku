package iam

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

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
)

var errFlowState = errors.New("iam: invalid or expired flow state")

// providerContext is how oauth2 and go-oidc pick up the guarded client.
func (s *Service) providerContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, s.idp)
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

// linkUserIDFor never links on cross-site navigations, which carry the Lax session cookie past the CSRF guard.
func linkUserIDFor(ctx context.Context, r *http.Request) string {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return ""
	}
	return actor.SubjectFromContext(ctx)
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
	raw, err := base64.RawURLEncoding.DecodeString(cookieFromHeader(r.Header, s.cookie))
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
	if _, err := s.svc.spent.Get(r.Context(), e.ID); err == nil {
		return e.State, "", errFlowState
	}
	return e.State, e.ID, nil
}

// spendFlow makes a finished flow single use. A full store is logged and skipped, it must never block a login.
func (s *Service) spendFlow(ctx context.Context, id string) {
	if err := s.spent.Set(ctx, id, nil, flowStateTTL); err != nil {
		slog.Warn("flow state not marked as spent", "error", err)
	}
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

// safeReturnTo only lets same-origin absolute paths through.
func safeReturnTo(p string) string {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || len(p) > maxReturnTo ||
		strings.HasPrefix(p, "/\\") || strings.ContainsAny(p, "\r\n") {
		return ""
	}
	return p
}

func fail(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, ssoErrorPath+"?error="+url.QueryEscape(msg), http.StatusSeeOther)
}
