package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/util"
)

// OIDCProvider is a resolved OIDC configuration: either the static public
// provider (google) or a workspace's custom enterprise provider loaded from
// the database. A nil dbConfig marks the static provider.
type OIDCProvider struct {
	dbConfig     *db.OidcProvider
	oauth2Config *oauth2.Config
	verifier     *oidc.IDTokenVerifier
}

// OIDCHandler serves the OpenID Connect flow: the static public google
// provider and workspace enterprise providers.
type OIDCHandler struct {
	cfg *config.Config
}

func NewOIDCHandler(cfg *config.Config) *OIDCHandler {
	return &OIDCHandler{cfg: cfg}
}

// oidcProviderCacheTTL bounds how long discovered endpoints stay cached. The
// workspace configuration (issuer, client, claims) is always read fresh from
// the database; only the discovery document — the one network round trip — is
// cached, so deactivating a provider takes effect immediately.
const oidcProviderCacheTTL = 10 * time.Minute

func (o *OIDCHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	providerID := r.URL.Query().Get("provider")
	if providerID == "" {
		writeJSONError(w, http.StatusBadRequest, "Provider required")
		return
	}

	config, err := o.getOIDCProvider(r.Context(), providerID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Provider configuration failed")
		return
	}

	nonce, err := crypto.RandomString(32)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Internal error")
		return
	}

	session := OAuthSession{
		ProviderID: providerID,
		Nonce:      nonce,
		LinkUserID: linkUserIDFromRequest(o.cfg, r),
	}

	authCodeOptions := []oauth2.AuthCodeOption{oidc.Nonce(nonce)}

	// Google doesn't require PKCE, but enterprise providers might.
	if config.dbConfig != nil && config.dbConfig.UsePkce {
		verifier := oauth2.GenerateVerifier()
		session.PKCEVerifier = verifier
		authCodeOptions = append(authCodeOptions, oauth2.S256ChallengeOption(verifier))
	}

	state, err := crypto.RandomString(32)
	if err != nil {
		slog.Error("Failed to generate state", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if err := startOAuthSession(o.cfg, w, r, state, session); err != nil {
		slog.Error("Failed to start OAuth session", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "Internal error")
		return
	}
	http.Redirect(
		w,
		r,
		config.oauth2Config.AuthCodeURL(state, authCodeOptions...),
		http.StatusTemporaryRedirect,
	)
}

func (o *OIDCHandler) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	redirect := o.cfg.FullURL()

	session, code := loadOAuthSession(o.cfg, w, r)
	if code != "" {
		authErrorRedirect(w, r, redirect, code)
		return
	}

	config, err := o.getOIDCProvider(r.Context(), session.ProviderID)
	if err != nil {
		authErrorRedirect(w, r, redirect, "provider_config_failed")
		return
	}

	var exchangeOpts []oauth2.AuthCodeOption
	if session.PKCEVerifier != "" {
		exchangeOpts = append(
			exchangeOpts,
			oauth2.SetAuthURLParam("code_verifier", session.PKCEVerifier),
		)
	}

	token, err := config.oauth2Config.Exchange(
		r.Context(),
		r.URL.Query().Get("code"),
		exchangeOpts...)
	if err != nil {
		authErrorRedirect(w, r, redirect, "token_exchange_failed")
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		authErrorRedirect(w, r, redirect, "no_id_token")
		return
	}

	idToken, err := config.verifier.Verify(r.Context(), rawIDToken)
	if err != nil || idToken.Nonce != session.Nonce {
		authErrorRedirect(w, r, redirect, "token_verification_failed")
		return
	}

	profile, err := extractOIDCClaims(idToken, config.dbConfig)
	if err != nil {
		authErrorRedirect(w, r, redirect, "invalid_claims")
		return
	}

	dbUser, err := handleOAuthUser(
		r.Context(),
		o.cfg,
		profile,
		idToken.Subject,
		session.ProviderID,
		config.dbConfig,
		session.LinkUserID,
	)
	if err != nil {
		redirectFailure(w, r, redirect, err)
		return
	}
	completeLogin(r.Context(), o.cfg, w, r, dbUser)
}

// getOIDCProvider resolves an OIDC provider. The workspace configuration is
// read fresh from the database on every call; the discovered endpoints are
// served from the shared cache for oidcProviderCacheTTL.
func (o *OIDCHandler) getOIDCProvider(
	ctx context.Context,
	providerID string,
) (*OIDCProvider, error) {
	var dbConfig *db.OidcProvider
	if providerID != "google" {
		// Pre-authentication lookup by provider ID, run as a system transaction.
		if err := o.cfg.Conn.WithTx(ctx, func(q *db.Queries) (err error) {
			dbConfig, err = q.GetOIDCProviderByID(ctx, providerID)
			return err
		}); err != nil {
			return nil, fmt.Errorf("failed to get provider from db: %w", err)
		}
	}

	clientID, clientSecret := o.cfg.GoogleClientID, o.cfg.GoogleClientSecret
	issuer, scopes := "https://accounts.google.com", []string{oidc.ScopeOpenID, "profile", "email"}
	if dbConfig != nil {
		if dbConfig.IssuerURL == nil || dbConfig.ClientID == nil {
			return nil, fmt.Errorf("oidc provider is missing issuer_url or client_id")
		}
		issuer = strings.TrimSpace(*dbConfig.IssuerURL)
		clientID, clientSecret = *dbConfig.ClientID, string(dbConfig.ClientSecret.Bytes())
		scopes = slices.DeleteFunc(
			dbConfig.Scopes,
			func(s string) bool { return s == oidc.ScopeOpenID },
		)
		scopes = append([]string{oidc.ScopeOpenID}, scopes...)
	}

	provider, err := o.discoverProvider(ctx, "oidc.discovery."+providerID, issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to discover oidc provider: %w", err)
	}

	return &OIDCProvider{
		dbConfig: dbConfig,
		oauth2Config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  o.cfg.FullURL() + "/oidc/callback",
			Endpoint:     provider.Endpoint(),
			Scopes:       scopes,
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: clientID}),
	}, nil
}

// discoverProvider returns the OIDC provider for issuer, rebuilding it from
// the cached discovery endpoints on a hit and running discovery otherwise.
func (o *OIDCHandler) discoverProvider(
	ctx context.Context,
	key, issuer string,
) (*oidc.Provider, error) {
	if data, err := o.cfg.Cache.Get(ctx, key); err == nil {
		var endpoints oidc.ProviderConfig
		if err := json.Unmarshal(data, &endpoints); err == nil && endpoints.IssuerURL == issuer {
			return endpoints.NewProvider(ctx), nil
		}
	}

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}

	var endpoints oidc.ProviderConfig
	if err := provider.Claims(&endpoints); err == nil {
		if data, err := json.Marshal(endpoints); err == nil {
			_ = o.cfg.Cache.Set(ctx, key, data, oidcProviderCacheTTL)
		}
	}
	return provider, nil
}

// oidcNamespace verifies that the user's email domain is a verified domain of
// the provider's workspace and returns the workspace ID used to namespace its
// identities, so identities from different organizations can never collide.
// Domain binding is what allows an organization to route its employees
// through its own IdP.
func oidcNamespace(
	ctx context.Context,
	cfg *config.Config,
	oidcConfig *db.OidcProvider,
	domain string,
) (string, error) {
	var owns bool
	err := cfg.Conn.WithTx(ctx, func(q *db.Queries) (err error) {
		owns, err = q.WorkspaceOwnsVerifiedDomain(
			ctx,
			&db.WorkspaceOwnsVerifiedDomainParams{
				WorkspaceID: oidcConfig.WorkspaceID,
				Domain:      domain,
			},
		)
		return err
	})
	if err != nil || !owns {
		return "", fmt.Errorf("email domain is not a verified domain of the selected provider")
	}
	return oidcConfig.WorkspaceID, nil
}

// finalizeEnterpriseLogin applies the policies of an enterprise (workspace
// OIDC) login: membership of the provider's workspace and profile sync from
// the IdP, which is the source of truth for its users. Social logins seed the
// profile once at creation and leave it to the user afterwards.
func finalizeEnterpriseLogin(
	ctx context.Context,
	q *db.Queries,
	user, profile *db.User,
	oidcConfig *db.OidcProvider,
) (*db.User, error) {
	if oidcConfig == nil {
		return user, nil
	}

	if err := q.AddWorkspaceMember(ctx, &db.AddWorkspaceMemberParams{
		UserID:      user.ID,
		WorkspaceID: oidcConfig.WorkspaceID,
	}); err != nil {
		return nil, fmt.Errorf("add workspace member: %w", err)
	}

	update := &db.UpdateUserParams{
		UserID:   user.ID,
		Username: &profile.Username,
	}
	// A nil or empty picture keeps the stored one: not every IdP sends a
	// picture claim.
	if profile.Picture != nil && *profile.Picture != "" {
		update.Picture = profile.Picture
	}
	if profile.Name != "" {
		update.Name = &profile.Name
	}
	updated, err := q.UpdateUser(ctx, update)
	if err != nil {
		return nil, fmt.Errorf("sync profile from provider: %w", err)
	}
	return updated, nil
}

// extractOIDCClaims extracts the user profile from the ID token using the
// provider's claim mappings.
func extractOIDCClaims(idToken *oidc.IDToken, oidcConfig *db.OidcProvider) (*db.User, error) {
	var allClaims map[string]any
	if err := idToken.Claims(&allClaims); err != nil {
		return nil, fmt.Errorf("failed to extract claims: %w", err)
	}

	getStringClaim := func(claimName string) string {
		if val, ok := allClaims[claimName]; ok {
			if str, ok := val.(string); ok {
				return str
			}
		}
		return ""
	}

	getBoolClaim := func(claimName string) bool {
		if val, ok := allClaims[claimName]; ok {
			if b, ok := val.(bool); ok {
				return b
			}
		}
		return false
	}

	// Defaults are Google claims; custom OIDC configs override them.
	emailClaim, nameClaim, usernameClaim, pictureClaim := "email", "name", "preferred_username", "picture"
	if oidcConfig != nil {
		emailClaim = oidcConfig.EmailClaim
		nameClaim = oidcConfig.NameClaim
		usernameClaim = oidcConfig.UsernameClaim
		pictureClaim = oidcConfig.PictureClaim
	}

	email := getStringClaim(emailClaim)
	name := getStringClaim(nameClaim)
	username := getStringClaim(usernameClaim)
	picture := getStringClaim(pictureClaim)

	emailVerified := getBoolClaim("email_verified")
	if oidcConfig != nil {
		emailVerified = emailVerified || getBoolClaim(oidcConfig.EmailClaim+"_verified")
	}

	if !emailVerified {
		return nil, fmt.Errorf("email not verified")
	}

	if email == "" {
		return nil, fmt.Errorf("email claim '%s' not found or empty", emailClaim)
	}

	username, err := util.GenerateUsername(email, username, []string{name})
	if err != nil || username == "" {
		return nil, fmt.Errorf("no username available from provider")
	}

	return &db.User{
		Name:     name,
		Username: username,
		Email:    email,
		Picture:  &picture,
	}, nil
}
