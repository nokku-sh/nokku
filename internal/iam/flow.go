package iam

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/nokku-sh/nokku/internal/cache"
	"github.com/nokku-sh/nokku/internal/crypto"
)

type oidcFlow struct {
	svc       *Service
	linker    *linker
	state     *sealed[authorizeState]
	providers *cache.Local[*oidc.Provider]
}

type authorizeState struct {
	ProviderID   string `json:"provider_id"`
	Nonce        string `json:"nonce,omitempty"`
	PKCEVerifier string `json:"pkce_verifier"`
	ReturnTo     string `json:"return_to,omitempty"`
	LinkUserID   string `json:"link_user_id,omitempty"`
}

func newOIDCFlow(svc *Service) *oidcFlow {
	return &oidcFlow{
		svc:       svc,
		linker:    &linker{svc: svc, credType: MethodOIDC},
		state:     &sealed[authorizeState]{svc: svc, cookie: flowCookieName, use: "oidc", ttl: flowStateTTL},
		providers: cache.NewLocal[*oidc.Provider](providerCacheTTL),
	}
}

func (s *Service) loginProvider(ctx context.Context, id string, m Method) (*SSOProvider, error) {
	p, err := s.GetSSOProvider(ctx, id)
	if err != nil {
		return nil, err
	}
	if !p.Enabled || p.Method != m {
		return nil, ErrNotFound
	}
	return p, nil
}

type authorizePrepare func(ctx context.Context, st *authorizeState, cfg *SSOProvider) (*oauth2.Config, []oauth2.AuthCodeOption, error)

func (s *Service) startLogin(
	w http.ResponseWriter,
	r *http.Request,
	m Method,
	store *sealed[authorizeState],
	prepare authorizePrepare,
) {
	ctx := r.Context()
	cfg, err := s.loginProvider(ctx, r.URL.Query().Get("provider"), m)
	if err != nil {
		fail(w, r, "provider not configured")
		return
	}
	st := &authorizeState{
		ProviderID:   cfg.ProviderID,
		PKCEVerifier: oauth2.GenerateVerifier(),
		ReturnTo:     safeReturnTo(r.URL.Query().Get("return_to")),
		LinkUserID:   linkUserIDFor(ctx, r),
	}
	conf, opts, err := prepare(ctx, st, cfg)
	if err != nil {
		slog.Warn("sso login start failed", "error", err, "provider", cfg.ProviderID)
		fail(w, r, "provider unavailable")
		return
	}
	key, err := store.put(w, *st)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	opts = append(opts, oauth2.S256ChallengeOption(st.PKCEVerifier))
	// #nosec G710 -- redirects to the provider authorization endpoint from its configuration.
	http.Redirect(w, r, conf.AuthCodeURL(key, opts...), http.StatusTemporaryRedirect)
}

// takeLogin writes the failure response itself. The state parameter has to
// name the flow this browser started, or the answer belongs to someone else.
func (s *Service) takeLogin(
	w http.ResponseWriter,
	r *http.Request,
	m Method,
	store *sealed[authorizeState],
) (st *authorizeState, flowID string, cfg *SSOProvider, ok bool) {
	q := r.URL.Query()
	if q.Get("error") != "" {
		fail(w, r, "login canceled")
		return nil, "", nil, false
	}
	state, flowID, err := store.take(r)
	if err != nil || subtle.ConstantTimeCompare([]byte(flowID), []byte(q.Get("state"))) != 1 {
		fail(w, r, "invalid or expired login")
		return nil, "", nil, false
	}
	cfg, err = s.loginProvider(r.Context(), state.ProviderID, m)
	if err != nil {
		fail(w, r, "provider not configured")
		return nil, "", nil, false
	}
	return &state, flowID, cfg, true
}

// Login links the identity to the signed-in user when there is one.
func (h *oidcFlow) Login(w http.ResponseWriter, r *http.Request) {
	h.svc.startLogin(
		w,
		r,
		MethodOIDC,
		h.state,
		func(ctx context.Context, st *authorizeState, cfg *SSOProvider) (*oauth2.Config, []oauth2.AuthCodeOption, error) {
			provider, err := h.discover(ctx, cfg.OIDC.IssuerURL)
			if err != nil {
				return nil, nil, err
			}
			if st.Nonce, err = crypto.RandomString(32); err != nil {
				return nil, nil, err
			}
			return h.oauth2Config(cfg.OIDC, provider), []oauth2.AuthCodeOption{oidc.Nonce(st.Nonce)}, nil
		},
	)
}

func (h *oidcFlow) Callback(w http.ResponseWriter, r *http.Request) {
	st, flowID, cfg, ok := h.svc.takeLogin(w, r, MethodOIDC, h.state)
	if !ok {
		return
	}
	ctx := h.svc.providerContext(r.Context())
	loginFailed := func(msg string, err error) {
		slog.Warn("oidc callback: "+msg, "error", err, "provider", cfg.ProviderID)
		fail(w, r, "login failed")
	}

	provider, err := h.discover(ctx, cfg.OIDC.IssuerURL)
	if err != nil {
		loginFailed("provider discovery failed", err)
		return
	}
	// RFC 9207 mix-up attack protection.
	if iss := r.URL.Query().Get("iss"); iss != "" &&
		!strings.EqualFold(strings.TrimSuffix(iss, "/"), strings.TrimSuffix(cfg.OIDC.IssuerURL, "/")) {
		loginFailed("issuer mismatch", nil)
		return
	}
	token, err := h.oauth2Config(cfg.OIDC, provider).Exchange(
		ctx,
		r.URL.Query().Get("code"),
		oauth2.VerifierOption(st.PKCEVerifier),
	)
	if err != nil {
		loginFailed("code exchange failed", err)
		return
	}
	rawIDToken, _ := token.Extra("id_token").(string)
	idToken, err := provider.Verifier(&oidc.Config{ClientID: cfg.OIDC.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		loginFailed("id token verification failed", err)
		return
	}
	// at_hash is optional in the code flow and Keycloak omits it.
	if idToken.AccessTokenHash != "" {
		if err := idToken.VerifyAccessToken(token.AccessToken); err != nil {
			loginFailed("access token hash mismatch", err)
			return
		}
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		loginFailed("claims decode failed", err)
		return
	}
	nonce, _ := claims["nonce"].(string)
	if subtle.ConstantTimeCompare([]byte(nonce), []byte(st.Nonce)) != 1 {
		loginFailed("nonce mismatch", nil)
		return
	}

	h.svc.completeSSO(w, r, h.linker, flowID, st.ReturnTo, flowLinkOptions{
		ProviderID:      cfg.ProviderID,
		WorkspaceID:     cfg.WorkspaceID,
		Subject:         idToken.Subject,
		Email:           claimString(claims, "email"),
		EmailVerified:   claimBool(claims, "email_verified"),
		Name:            claimString(claims, "name"),
		Picture:         claimString(claims, "picture"),
		JITProvisioning: cfg.OIDC.JITProvisioning,
		LinkUserID:      st.LinkUserID,
	})
}

func (h *oidcFlow) discover(ctx context.Context, issuer string) (*oidc.Provider, error) {
	if p, ok := h.providers.Get(issuer); ok {
		return p, nil
	}
	provider, err := oidc.NewProvider(h.svc.providerContext(ctx), issuer)
	if err != nil {
		return nil, err
	}
	h.providers.Put(issuer, provider)
	return provider, nil
}

func (h *oidcFlow) oauth2Config(cfg *OIDCProvider, provider *oidc.Provider) *oauth2.Config {
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeProfile, oidc.ScopeEmail}
	}
	if !slices.Contains(scopes, oidc.ScopeOpenID) {
		scopes = append([]string{oidc.ScopeOpenID}, scopes...)
	}
	return &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  h.svc.baseURL + "/oidc/callback",
		Scopes:       scopes,
	}
}
