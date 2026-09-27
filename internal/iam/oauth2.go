package iam

// The plain OAuth2 authorization-code flow for providers without OIDC
// discovery (GitHub).

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"golang.org/x/oauth2"
)

// profileBodyLimit caps the provider profile and email responses.
const profileBodyLimit = 1 << 20

// oauth2Flow serves the OAuth2 authorization-code flow.
type oauth2Flow struct {
	svc    *Service
	linker *linker
	state  *state[authorizeState]
}

func newOAuth2Flow(svc *Service) *oauth2Flow {
	return &oauth2Flow{
		svc:    svc,
		linker: &linker{svc: svc, credType: MethodOAuth2},
		state:  newState[authorizeState](svc.cache, "oauth2:authorize:", flowStateTTL),
	}
}

// Login starts the authorization-code flow.
func (h *oauth2Flow) Login(w http.ResponseWriter, r *http.Request) {
	h.svc.startLogin(w, r, MethodOAuth2, h.state,
		func(_ context.Context, _ *authorizeState, cfg *SSOProvider) (*oauth2.Config, []oauth2.AuthCodeOption, error) {
			return h.oauth2Config(cfg.OAuth2), nil, nil
		})
}

// Callback fetches the profile, resolves the user, and issues a session.
func (h *oauth2Flow) Callback(w http.ResponseWriter, r *http.Request) {
	st, cfg, ok := h.svc.takeLogin(w, r, MethodOAuth2, h.state)
	if !ok {
		return
	}
	ctx := h.svc.providerContext(r.Context())
	token, err := h.oauth2Config(cfg.OAuth2).Exchange(
		ctx,
		r.URL.Query().Get("code"),
		oauth2.VerifierOption(st.PKCEVerifier),
	)
	if err != nil {
		slog.Warn("oauth2 callback: code exchange failed", "error", err, "provider", cfg.ProviderID)
		fail(w, r, "login failed")
		return
	}
	var profile map[string]any
	if err := oauthGet(ctx, token, cfg.OAuth2.UserInfoURL, &profile); err != nil {
		slog.Warn("oauth2 callback: profile fetch failed", "error", err, "provider", cfg.ProviderID)
		fail(w, r, "login failed")
		return
	}
	subject := claimString(profile, "id", "sub")
	if subject == "" {
		fail(w, r, "login failed")
		return
	}
	email := claimString(profile, "email")
	verified := claimBool(profile, "email_verified")
	if cfg.OAuth2.EmailURL != "" {
		// GitHub never marks the profile email verified, the emails endpoint
		// is the only source for that.
		email, verified = fetchEmail(ctx, cfg.OAuth2, token)
	}

	h.svc.completeSSO(w, r, h.linker, st.ReturnTo, flowLinkOptions{
		ProviderID:      cfg.ProviderID,
		WorkspaceID:     cfg.WorkspaceID,
		Subject:         subject,
		Email:           email,
		EmailVerified:   verified,
		Name:            claimString(profile, "name", "login"),
		Picture:         claimString(profile, "avatar_url"),
		JITProvisioning: cfg.OAuth2.JITProvisioning,
		LinkUserID:      st.LinkUserID,
	})
}

// fetchEmail picks the primary verified address from an email-list
// endpoint, else any verified one. Unverified addresses never match an
// account, so they are not worth returning.
func fetchEmail(ctx context.Context, cfg *OAuth2Provider, tok *oauth2.Token) (string, bool) {
	var entries []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := oauthGet(ctx, tok, cfg.EmailURL, &entries); err != nil {
		return "", false
	}
	var fallback string
	for _, e := range entries {
		if !e.Verified {
			continue
		}
		if e.Primary {
			return e.Email, true
		}
		if fallback == "" {
			fallback = e.Email
		}
	}
	return fallback, fallback != ""
}

func (h *oauth2Flow) oauth2Config(cfg *OAuth2Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     oauth2.Endpoint{AuthURL: cfg.AuthURL, TokenURL: cfg.TokenURL},
		RedirectURL:  h.svc.baseURL + "/oauth/callback",
		Scopes:       cfg.Scopes,
	}
}

// oauthGet performs an authenticated GET and decodes the JSON body into
// dst. ctx carries the guarded provider client.
func oauthGet(ctx context.Context, tok *oauth2.Token, url string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := oauth2.NewClient(ctx, oauth2.StaticTokenSource(tok)).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return errors.New("oauth2: " + resp.Status)
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, profileBodyLimit))
	dec.UseNumber()
	return dec.Decode(dst)
}
