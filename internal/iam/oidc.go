package iam

// The OIDC authorization-code flow, ported from kagi. Provider configs come
// from the sso_providers table; discovered endpoints are cached in memory.

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

// oidcFlow serves the OIDC authorization-code flow.
type oidcFlow struct {
	svc         *Service
	linker      *linker
	authorize   *flowAuthorize
	errRedirect string
	providers   *cache.Local[*oidc.Provider]
}

// OAuth2Provider describes a plain OAuth2 provider without OIDC discovery,
// such as GitHub.
type OAuth2Provider struct {
	AuthURL         string   `json:"auth_url"`
	TokenURL        string   `json:"token_url"`
	UserInfoURL     string   `json:"user_info_url"`
	EmailURL        string   `json:"email_url,omitempty"` // used when the profile has no email
	RedirectURL     string   `json:"redirect_url,omitempty"`
	Scopes          []string `json:"scopes,omitempty"`
	ClientSecret    string   `json:"client_secret,omitempty"` // only ever at rest inside the encrypted config blob
	ClientID        string   `json:"client_id"`
	JITProvisioning bool     `json:"jit_provisioning,omitempty"`
	EnforceSSO      bool     `json:"enforce_sso,omitempty"`
}

// newOIDCFlow builds the OIDC flow handler.
func newOIDCFlow(svc *Service) *oidcFlow {
	return &oidcFlow{
		svc:         svc,
		linker:      &linker{svc: svc, credType: MethodOIDC, OnSSOLogin: svc.OnSSOLogin},
		authorize:   newFlowAuthorize(svc.cache, "oidc:authorize:"),
		errRedirect: svc.baseURL + "/auth-error",
		providers:   cache.NewLocal[*oidc.Provider](providerCacheTTL),
	}
}

// newOAuth2Flow builds the plain OAuth2 flow handler.
func newOAuth2Flow(svc *Service) *oauth2Flow {
	return &oauth2Flow{
		svc:         svc,
		linker:      &linker{svc: svc, credType: MethodOAuth2, OnSSOLogin: svc.OnSSOLogin},
		authorize:   newFlowAuthorize(svc.cache, "oauth2:authorize:"),
		errRedirect: svc.baseURL + "/auth-error",
	}
}

// flowAuthorizeState is the cross-request payload carried through the
// authorization redirect under the OAuth 2.0 "state" value.
type flowAuthorizeState struct {
	WorkspaceID  string `json:"workspace_id,omitempty"`
	ProviderID   string `json:"provider_id"`
	Nonce        string `json:"nonce,omitempty"`
	PKCEVerifier string `json:"pkce_verifier,omitempty"`
	ReturnTo     string `json:"return_to,omitempty"`
	LinkUserID   string `json:"link_user_id,omitempty"`
	// FlowCookie is the value of the browser-scoped flow cookie; the
	// callback must present the same value (login CSRF binding).
	FlowCookie string `json:"flow_cookie,omitempty"`
}

// flowAuthorize stores single-use flowAuthorizeState values under a per-flow
// cache prefix.
type flowAuthorize struct {
	state *state[flowAuthorizeState]
}

func newFlowAuthorize(c Cache, prefix string) *flowAuthorize {
	return &flowAuthorize{state: newState[flowAuthorizeState](c, prefix, flowStateTTL)}
}

// Put stores st under the random state parameter and returns it.
func (a *flowAuthorize) Put(ctx context.Context, st *flowAuthorizeState) (string, error) {
	stateValue, err := crypto.RandomString(32)
	if err != nil {
		return "", err
	}
	if err := a.state.Put(ctx, stateValue, *st); err != nil {
		return "", err
	}
	return stateValue, nil
}

// Take loads and consumes the state for stateValue.
func (a *flowAuthorize) Take(ctx context.Context, stateValue string) (*flowAuthorizeState, error) {
	st, err := a.state.Take(ctx, stateValue)
	if err != nil {
		return nil, err
	}
	return &st, nil
}

// resolveForLogin resolves the flow's provider config for a login request.
// When no provider matches, it falls back to the provider's workspace via
// the email's verified domain: home realm discovery lands on a workspace
// other than the login request's. It returns the effective workspace.
// Enterprise providers pin their workspace: a login that starts without
// workspace context resolves to the provider's workspace, so JIT-provisioned
// users become members there instead of landing with no workspace. Social
// rows carry no workspace and leave the passed value untouched.
func (s *Service) resolveForLogin(
	ctx context.Context,
	workspaceID, providerID, domain string,
) (string, *SSOProvider, error) {
	cfg, err := s.GetSSOProvider(ctx, providerID)
	if err == nil {
		if workspaceID == "" && cfg.WorkspaceID != "" {
			workspaceID = cfg.WorkspaceID
		}
		return workspaceID, cfg, nil
	}
	if d, derr := s.GetVerifiedTenantDomain(
		ctx,
		domain,
	); derr == nil &&
		d.ProviderID == providerID {
		if cfg2, rerr := s.GetSSOProvider(ctx, providerID); rerr == nil {
			return d.WorkspaceID, cfg2, nil
		}
	}
	return workspaceID, nil, ErrNotFound
}

// Login starts the OIDC authorization-code flow. Behind Middleware with a
// live session, the identity links to the signed-in user.
func (h *oidcFlow) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	providerID := r.URL.Query().Get("provider")
	if providerID == "" {
		WriteError(w, http.StatusBadRequest, "missing_provider", "missing provider")
		return
	}

	workspaceID, cfg, err := h.svc.resolveForLogin(
		ctx, "", providerID, r.URL.Query().Get("domain"),
	)
	if err != nil {
		Fail(w, r, h.errRedirect, "provider not configured")
		return
	}

	st := &flowAuthorizeState{
		WorkspaceID: workspaceID,
		ProviderID:  providerID,
		ReturnTo:    SafeReturnTo(r.URL.Query().Get("return_to")),
		LinkUserID:  linkUserIDFor(ctx, r),
	}

	provider, err := h.discover(ctx, cfg.OIDC.IssuerURL)
	if err != nil {
		Fail(w, r, h.errRedirect, "provider discovery failed")
		return
	}
	st.FlowCookie = startFlowBinding(w, false)
	nonce, err := crypto.RandomString(32)
	if err != nil {
		Fail(w, r, h.errRedirect, "provider discovery failed")
		return
	}
	st.Nonce = nonce
	st.PKCEVerifier = oauth2.GenerateVerifier()
	cfg.OIDC.RedirectURL = h.svc.baseURL + "/oidc/callback"
	authOpts := []oauth2.AuthCodeOption{
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(st.PKCEVerifier),
	}

	stateValue, err := h.authorize.Put(ctx, st)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}

	// #nosec G710 -- redirects to the provider authorization endpoint from its configuration.
	http.Redirect(
		w,
		r,
		h.oauth2Config(cfg.OIDC, provider).AuthCodeURL(stateValue, authOpts...),
		http.StatusTemporaryRedirect,
	)
}

// Callback completes the flow: verifies the ID token, resolves the user,
// issues a session, and redirects to returnTo.
func (h *oidcFlow) Callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	if q.Get("error") != "" {
		Fail(w, r, h.errRedirect, "login canceled")
		return
	}

	st, err := h.authorize.Take(ctx, q.Get("state"))
	if err != nil {
		Fail(w, r, h.errRedirect, "invalid or expired login")
		return
	}
	// The callback must arrive in the browser that started the flow.
	if !checkFlowBinding(r, st.FlowCookie) {
		Fail(w, r, h.errRedirect, "invalid or expired login")
		return
	}
	cfg, err := h.svc.GetSSOProvider(ctx, st.ProviderID)
	if err != nil {
		Fail(w, r, h.errRedirect, "provider not configured")
		return
	}
	// Login set the redirect URL on its in-memory copy; the callback reloads
	// the stored config, so set it again. Providers like Keycloak reject the
	// exchange when the redirect_uri the code was issued for is missing.
	cfg.OIDC.RedirectURL = h.svc.baseURL + "/oidc/callback"

	provider, err := h.discover(ctx, cfg.OIDC.IssuerURL)
	if err != nil {
		Fail(w, r, h.errRedirect, "provider discovery failed")
		return
	}
	// RFC 9207: when the authorization response carries the iss parameter,
	// it must match the issuer, or the response may be a mix-up attack.
	if iss := q.Get("iss"); iss != "" &&
		!strings.EqualFold(
			strings.TrimSuffix(iss, "/"),
			strings.TrimSuffix(cfg.OIDC.IssuerURL, "/"),
		) {
		Fail(w, r, h.errRedirect, "login failed")
		return
	}

	exchangeCtx := context.WithValue(
		ctx,
		oauth2.HTTPClient,
		&http.Client{Timeout: providerHTTPTimeout},
	)
	token, err := h.oauth2Config(cfg.OIDC, provider).Exchange(
		exchangeCtx,
		q.Get("code"),
		oauth2.SetAuthURLParam("code_verifier", st.PKCEVerifier),
	)
	if err != nil {
		slog.Warn("oidc callback: code exchange failed", "error", err, "provider", cfg.ProviderID)
		Fail(w, r, h.errRedirect, "login failed")
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		slog.Warn("oidc callback: token response has no id_token", "provider", cfg.ProviderID)
		Fail(w, r, h.errRedirect, "login failed")
		return
	}
	idToken, err := provider.Verifier(&oidc.Config{ClientID: cfg.OIDC.ClientID}).
		Verify(ctx, rawIDToken)
	if err != nil {
		slog.Warn(
			"oidc callback: id token verification failed",
			"error",
			err,
			"provider",
			cfg.ProviderID,
		)
		Fail(w, r, h.errRedirect, "login failed")
		return
	}
	// at_hash is optional in the authorization code flow and some providers
	// (Keycloak) omit it, so only compare when the claim is present.
	if idToken.AccessTokenHash != "" {
		if err := idToken.VerifyAccessToken(token.AccessToken); err != nil {
			slog.Warn(
				"oidc callback: access token hash mismatch",
				"error",
				err,
				"provider",
				cfg.ProviderID,
			)
			Fail(w, r, h.errRedirect, "login failed")
			return
		}
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		slog.Warn(
			"oidc callback: id token claims decode failed",
			"error",
			err,
			"provider",
			cfg.ProviderID,
		)
		Fail(w, r, h.errRedirect, "login failed")
		return
	}
	// A mismatch means replay or a misbehaving provider.
	nonce, _ := claims["nonce"].(string)
	if subtle.ConstantTimeCompare([]byte(nonce), []byte(st.Nonce)) != 1 {
		Fail(w, r, h.errRedirect, "login failed")
		return
	}

	h.complete(ctx, w, r, st, flowLinkOptions{
		ProviderID:      cfg.ProviderID,
		Subject:         idToken.Subject,
		Email:           claimString(claims, "email"),
		EmailVerified:   claimBool(claims, "email_verified"),
		Name:            claimString(claims, "name"),
		Picture:         claimString(claims, "picture"),
		JITProvisioning: cfg.OIDC.JITProvisioning,
	})
}

// complete resolves the identity, issues the session, and redirects.
func (h *oidcFlow) complete(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	st *flowAuthorizeState,
	opts flowLinkOptions,
) {
	h.svc.completeSSO(ctx, w, r, h.linker, st, opts, h.errRedirect)
}

func (h *oidcFlow) discover(ctx context.Context, issuer string) (*oidc.Provider, error) {
	if p, ok := h.providers.Get(issuer); ok {
		return p, nil
	}
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	h.providers.Put(issuer, provider)
	return provider, nil
}

func (h *oidcFlow) oauth2Config(cfg *OIDCProvider, provider *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.RedirectURL,
		Scopes:       oidcScopes(cfg.Scopes),
	}
}

func oidcScopes(s []string) []string {
	if len(s) == 0 {
		return []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail}
	}
	if slices.Contains(s, oidc.ScopeOpenID) {
		return s
	}
	return append([]string{oidc.ScopeOpenID}, s...)
}
