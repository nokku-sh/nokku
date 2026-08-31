package iam

// The plain OAuth2 authorization-code flow for providers without OIDC
// discovery (GitHub), ported from kagi.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"golang.org/x/oauth2"
)

// profileBodyLimit caps the provider profile and email responses iam is
// willing to buffer.
const profileBodyLimit = 1 << 20

// emailEntry is one entry of an email-list endpoint response.
type emailEntry struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// oauth2Flow serves the OAuth2 authorization-code flow.
type oauth2Flow struct {
	svc         *Service
	linker      *linker
	authorize   *flowAuthorize
	errRedirect string
}

// Login starts the authorization-code flow.
func (h *oauth2Flow) Login(w http.ResponseWriter, r *http.Request) {
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
		LinkUserID:  flowLinkUserID(ctx),
	}
	st.PKCEVerifier = oauth2.GenerateVerifier()

	stateValue, err := h.authorize.Put(ctx, st)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}

	cfg.OAuth2.RedirectURL = h.svc.baseURL + "/oauth/callback"
	// #nosec G710 -- redirects to the provider authorization endpoint from its configuration.
	http.Redirect(
		w,
		r,
		h.oauth2Config(cfg.OAuth2).AuthCodeURL(stateValue),
		http.StatusTemporaryRedirect,
	)
}

// Callback completes the flow: fetches the profile, resolves the user, and
// issues a session.
func (h *oauth2Flow) Callback(w http.ResponseWriter, r *http.Request) {
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
	cfg, err := h.svc.GetSSOProvider(ctx, st.ProviderID)
	if err != nil {
		Fail(w, r, h.errRedirect, "provider not configured")
		return
	}

	exchangeCtx := context.WithValue(
		ctx,
		oauth2.HTTPClient,
		&http.Client{Timeout: providerHTTPTimeout},
	)
	token, err := h.oauth2Config(cfg.OAuth2).Exchange(
		exchangeCtx,
		q.Get("code"),
		oauth2.SetAuthURLParam("code_verifier", st.PKCEVerifier),
	)
	if err != nil {
		slog.Warn("oauth2 callback: code exchange failed", "error", err, "provider", cfg.ProviderID)
		Fail(w, r, h.errRedirect, "login failed")
		return
	}

	profile, err := h.fetchProfile(ctx, cfg.OAuth2, token)
	if err != nil {
		slog.Warn("oauth2 callback: profile fetch failed", "error", err, "provider", cfg.ProviderID)
		Fail(w, r, h.errRedirect, "login failed")
		return
	}

	subject := claimString(profile, "id", "sub")
	if subject == "" {
		Fail(w, r, h.errRedirect, "login failed")
		return
	}
	email := claimString(profile, "email")
	verified := claimBool(profile, "email_verified")
	if email == "" && cfg.OAuth2.EmailURL != "" {
		email, verified = h.fetchEmail(ctx, cfg.OAuth2, token)
	}

	h.svc.completeSSO(ctx, w, r, h.linker, st, flowLinkOptions{
		ProviderID:      cfg.ProviderID,
		Subject:         subject,
		Email:           email,
		EmailVerified:   verified,
		Name:            claimString(profile, "name", "login"),
		Picture:         claimString(profile, "avatar_url"),
		JITProvisioning: cfg.OAuth2.JITProvisioning,
	}, h.errRedirect)
}

func (h *oauth2Flow) fetchProfile(
	ctx context.Context,
	cfg *OAuth2Provider,
	tok *oauth2.Token,
) (map[string]any, error) {
	resp, err := oauthGet(ctx, tok, cfg.UserInfoURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, errors.New("oauth2: userinfo request failed")
	}

	dec := json.NewDecoder(io.LimitReader(resp.Body, profileBodyLimit))
	dec.UseNumber()
	var profile map[string]any
	if err := dec.Decode(&profile); err != nil {
		return nil, err
	}
	return profile, nil
}

// fetchEmail is a best-effort fetch for providers that keep email out of the
// profile. It returns the chosen address and whether it is verified.
func (h *oauth2Flow) fetchEmail(
	ctx context.Context,
	cfg *OAuth2Provider,
	tok *oauth2.Token,
) (string, bool) {
	resp, err := oauthGet(ctx, tok, cfg.EmailURL)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()

	var entries []emailEntry
	if err := json.NewDecoder(io.LimitReader(resp.Body, profileBodyLimit)).
		Decode(&entries); err != nil {
		return "", false
	}

	var fallback string
	var fallbackVerified bool
	for _, e := range entries {
		if fallback == "" {
			fallback, fallbackVerified = e.Email, e.Verified
		}
		if e.Primary && e.Verified {
			return e.Email, true
		}
	}
	for _, e := range entries {
		if e.Primary {
			return e.Email, e.Verified
		}
	}
	for _, e := range entries {
		if e.Verified {
			return e.Email, true
		}
	}
	return fallback, fallbackVerified
}

func (h *oauth2Flow) oauth2Config(cfg *OAuth2Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  cfg.AuthURL,
			TokenURL: cfg.TokenURL,
		},
		RedirectURL: cfg.RedirectURL,
		Scopes:      cfg.Scopes,
	}
}

// oauthGet performs an authenticated GET, carrying ctx so cancellation
// works. The URL comes from host-configured provider fields, never request
// input.
func oauthGet(ctx context.Context, tok *oauth2.Token, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(tok))
	client.Timeout = providerHTTPTimeout
	return client.Do(req)
}
