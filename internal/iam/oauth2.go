package iam

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"golang.org/x/oauth2"
)

const profileBodyLimit = 1 << 20

// oauth2Flow is for providers without OIDC discovery, like GitHub.
type oauth2Flow struct {
	svc    *Service
	linker *linker
	state  *sealed[authorizeState]
}

func newOAuth2Flow(svc *Service) *oauth2Flow {
	return &oauth2Flow{
		svc:    svc,
		linker: &linker{svc: svc, credType: MethodOAuth2},
		state:  &sealed[authorizeState]{svc: svc, cookie: flowCookieName, use: "oauth2", ttl: flowStateTTL},
	}
}

func (h *oauth2Flow) Login(w http.ResponseWriter, r *http.Request) {
	h.svc.startLogin(w, r, MethodOAuth2, h.state,
		func(_ context.Context, _ *authorizeState, cfg *SSOProvider) (*oauth2.Config, []oauth2.AuthCodeOption, error) {
			return h.oauth2Config(cfg.OAuth2), nil, nil
		})
}

func (h *oauth2Flow) Callback(w http.ResponseWriter, r *http.Request) {
	st, flowID, cfg, ok := h.svc.takeLogin(w, r, MethodOAuth2, h.state)
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
		// GitHub only reports verification on the emails endpoint.
		email, verified = fetchEmail(ctx, cfg.OAuth2, token)
	}

	h.svc.completeSSO(w, r, h.linker, flowID, st.ReturnTo, flowLinkOptions{
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

// fetchEmail prefers the primary verified address. Unverified ones never
// match an account, so they are skipped.
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
