package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/sync/singleflight"

	"github.com/nokku-sh/nokku/internal/authn"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/email"
	"github.com/nokku-sh/nokku/internal/util"
)

type UnifiedUser struct {
	ProviderID string
	Provider   string
	Email      string
	Name       string
	Username   string
	AvatarURL  string
}

// OAuthSession represents the temporary state stored in cache during the flow.
type OAuthSession struct {
	ProviderID   string `json:"provider_id"`
	Nonce        string `json:"nonce,omitempty"`
	PKCEVerifier string `json:"pkce_verifier,omitempty"`
	LinkUserID   string `json:"link_user_id,omitempty"`
}

type OAuthHandler struct {
	cfg           *config.Config
	providerCache sync.Map // Local memory cache for *OIDCProvider to avoid network discovery penalties
	sf            singleflight.Group
}

type OIDCProvider struct {
	dbConfig     *db.OidcProvider
	oauth2Config *oauth2.Config
	verifier     *oidc.IDTokenVerifier
}

func NewOAuthHandler(cfg *config.Config) *OAuthHandler {
	return &OAuthHandler{cfg: cfg}
}

func (o *OAuthHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	providerID := r.URL.Query().Get("provider")
	if providerID == "" {
		writeJSONError(w, http.StatusBadRequest, "Provider required")
		return
	}

	state, err := crypto.RandomString(32)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Internal error")
		return
	}

	session := OAuthSession{ProviderID: providerID}
	if r.URL.Query().Get("link") == "true" {
		if tokenStr := authn.GetAccessToken(r.Header); tokenStr != "" {
			if claims, err := o.cfg.Authn.VerifyToken(tokenStr); err == nil {
				session.LinkUserID = claims.UserID
			}
		}
	}

	var authCodeOptions []oauth2.AuthCodeOption
	var authURL string

	// Handle Static vs Custom Providers
	if providerID == "github" {
		conf := &oauth2.Config{
			ClientID:     o.cfg.GitHubClientID,
			ClientSecret: o.cfg.GitHubClientSecret,
			RedirectURL:  o.cfg.FullURL() + "/oauth/callback",
			Scopes:       []string{"user:email", "read:user"},
			Endpoint:     github.Endpoint,
		}
		authURL = conf.AuthCodeURL(state)
	} else {
		// Handle Google and Custom OIDC Providers
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
		session.Nonce = nonce
		authCodeOptions = append(authCodeOptions, oidc.Nonce(nonce))

		// Google doesn't enforce PKCE, but custom ones might
		if config.dbConfig != nil && config.dbConfig.UsePkce {
			verifier := oauth2.GenerateVerifier()
			session.PKCEVerifier = verifier
			authCodeOptions = append(authCodeOptions, oauth2.S256ChallengeOption(verifier))
		}

		authURL = config.oauth2Config.AuthCodeURL(state, authCodeOptions...)
	}

	// Save session to cache
	b, err := json.Marshal(session)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Internal error")
		return
	}
	_ = o.cfg.Cache.Set(r.Context(), "oauth_state."+state, b, 10*time.Minute)

	// Drop CSRF cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		MaxAge:   600, // 10 minutes
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func (o *OAuthHandler) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	redirect := o.cfg.FullURL()

	// Verify State & CSRF
	stateCookie, err := r.Cookie("oauth_state")
	stateQuery := r.URL.Query().Get("state")
	if err != nil || stateCookie.Value != stateQuery {
		http.Redirect(w, r, redirect+"?error=invalid_state", http.StatusTemporaryRedirect)
		return
	}

	// Clear the cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		MaxAge:   -1,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	sessionData, err := o.cfg.Cache.Get(r.Context(), "oauth_state."+stateQuery)
	if err != nil || sessionData == nil {
		http.Redirect(w, r, redirect+"?error=session_expired", http.StatusTemporaryRedirect)
		return
	}
	_ = o.cfg.Cache.Delete(r.Context(), "oauth_state."+stateQuery)

	var session OAuthSession
	if err := json.Unmarshal(sessionData, &session); err != nil {
		http.Redirect(w, r, redirect+"?error=invalid_session", http.StatusTemporaryRedirect)
		return
	}

	code := r.URL.Query().Get("code")
	var user UnifiedUser
	var dbOidc *db.OidcProvider

	// Extract User based on Provider Type
	if session.ProviderID == "github" {
		conf := &oauth2.Config{
			ClientID:     o.cfg.GitHubClientID,
			ClientSecret: o.cfg.GitHubClientSecret,
			RedirectURL:  o.cfg.FullURL() + "/oauth/callback",
			Endpoint:     github.Endpoint,
		}
		token, err := conf.Exchange(r.Context(), code)
		if err != nil {
			http.Redirect(
				w,
				r,
				redirect+"?error=token_exchange_failed",
				http.StatusTemporaryRedirect,
			)
			return
		}
		user, err = fetchGitHubUser(r.Context(), token)
		if err != nil {
			http.Redirect(w, r, redirect+"?error=github_fetch_failed", http.StatusTemporaryRedirect)
			return
		}
	} else {
		// Handle Google and Custom OIDC
		config, err := o.getOIDCProvider(r.Context(), session.ProviderID)
		if err != nil {
			http.Redirect(
				w,
				r,
				redirect+"?error=provider_config_failed",
				http.StatusTemporaryRedirect,
			)
			return
		}
		dbOidc = config.dbConfig

		var exchangeOpts []oauth2.AuthCodeOption
		if session.PKCEVerifier != "" {
			exchangeOpts = append(
				exchangeOpts,
				oauth2.SetAuthURLParam("code_verifier", session.PKCEVerifier),
			)
		}

		token, err := config.oauth2Config.Exchange(r.Context(), code, exchangeOpts...)
		if err != nil {
			http.Redirect(
				w,
				r,
				redirect+"?error=token_exchange_failed",
				http.StatusTemporaryRedirect,
			)
			return
		}

		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			http.Redirect(w, r, redirect+"?error=no_id_token", http.StatusTemporaryRedirect)
			return
		}

		idToken, err := config.verifier.Verify(r.Context(), rawIDToken)
		if err != nil || idToken.Nonce != session.Nonce {
			http.Redirect(
				w,
				r,
				redirect+"?error=token_verification_failed",
				http.StatusTemporaryRedirect,
			)
			return
		}

		user, err = extractOIDCClaims(idToken, dbOidc)
		if err != nil {
			http.Redirect(w, r, redirect+"?error=invalid_claims", http.StatusTemporaryRedirect)
			return
		}
		user.Provider = session.ProviderID
	}

	dbUser, err := o.handleOAuthUser(r.Context(), user, dbOidc, session.LinkUserID)
	if err != nil {
		// Never leak backend details into the redirect URL; the frontend
		// only needs a generic failure indicator.
		slog.Debug("oauth login failed", "error", err, "provider", session.ProviderID)
		http.Redirect(
			w,
			r,
			redirect+"?error=user_failed",
			http.StatusTemporaryRedirect,
		)
		return
	}

	o.cfg.Authn.AccessCookie(r.Context(), w.Header(), dbUser)
	o.cfg.Authn.RefreshCookie(r.Context(), w.Header(), dbUser)
	syncWebDevice(r.Context(), o.cfg, r.Header, w.Header(), r.RemoteAddr, dbUser)
	http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
}

func (o *OAuthHandler) getOIDCProvider(
	ctx context.Context,
	providerID string,
) (*OIDCProvider, error) {
	var dbConfig *db.OidcProvider
	var err error

	// Fetch DB config first to get UpdatedAt timestamp for cache validation
	if providerID != "google" {
		dbConfig, err = o.cfg.Conn.Q.GetOIDCProviderByID(ctx, providerID)
		if err != nil {
			return nil, fmt.Errorf("failed to get provider from db: %w", err)
		}
	}

	// Check local memory cache first to avoid network penalty
	if cachedAny, ok := o.providerCache.Load(providerID); ok {
		cached, ok := cachedAny.(*OIDCProvider)
		if !ok {
			o.providerCache.Delete(providerID)
		} else if dbConfig == nil ||
			(cached.dbConfig != nil && cached.dbConfig.UpdatedAt.Equal(dbConfig.UpdatedAt)) {
			return cached, nil
		}
	}

	v, err, _ := o.sf.Do(providerID, func() (any, error) {
		var providerConf *OIDCProvider

		// Handle Google static config
		if providerID == "google" {
			provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
			if err != nil {
				return nil, err
			}
			providerConf = &OIDCProvider{
				dbConfig: nil, // Indicates static
				oauth2Config: &oauth2.Config{
					ClientID:     o.cfg.GoogleClientID,
					ClientSecret: o.cfg.GoogleClientSecret,
					RedirectURL:  o.cfg.FullURL() + "/oauth/callback",
					Endpoint:     provider.Endpoint(),
					Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
				},
				verifier: provider.Verifier(&oidc.Config{ClientID: o.cfg.GoogleClientID}),
			}
		} else {
			// Handle custom DB providers using the already fetched dbConfig
			provider, err := oidc.NewProvider(ctx, strings.TrimSpace(*dbConfig.IssuerURL))
			if err != nil {
				return nil, fmt.Errorf("failed to discover oidc provider: %w", err)
			}

			scopes := slices.DeleteFunc(
				dbConfig.Scopes,
				func(s string) bool { return s == oidc.ScopeOpenID },
			)
			scopes = append([]string{oidc.ScopeOpenID}, scopes...)

			providerConf = &OIDCProvider{
				dbConfig: dbConfig,
				oauth2Config: &oauth2.Config{
					ClientID:     *dbConfig.ClientID,
					ClientSecret: string(dbConfig.ClientSecret.Bytes()),
					RedirectURL:  o.cfg.FullURL() + "/oauth/callback",
					Endpoint:     provider.Endpoint(),
					Scopes:       scopes,
				},
				verifier: provider.Verifier(&oidc.Config{ClientID: *dbConfig.ClientID}),
			}
		}

		// Cache in memory for subsequent requests
		o.providerCache.Store(providerID, providerConf)
		return providerConf, nil
	})

	if err != nil {
		return nil, err
	}
	provider, ok := v.(*OIDCProvider)
	if !ok {
		return nil, fmt.Errorf("unexpected type for provider %s", providerID)
	}
	return provider, nil
}

func fetchGitHubUser(ctx context.Context, token *oauth2.Token) (UnifiedUser, error) {
	client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))
	var user UnifiedUser
	user.Provider = "github"

	// Fetch base profile
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return user, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return user, err
	}
	defer func() { _ = resp.Body.Close() }()

	var ghUser struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ghUser); err != nil {
		return user, err
	}

	// Fetch emails
	reqEmails, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"https://api.github.com/user/emails",
		nil,
	)
	if err != nil {
		return user, err
	}
	respEmails, err := client.Do(reqEmails)
	if err != nil {
		return user, err
	}
	defer func() { _ = respEmails.Body.Close() }()

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(respEmails.Body).Decode(&emails); err == nil {
		for _, e := range emails {
			if e.Primary && e.Verified {
				user.Email = e.Email
				break
			}
		}
	}

	if user.Email == "" {
		return user, fmt.Errorf("no verified primary email found on github")
	}

	user.ProviderID = strconv.FormatInt(ghUser.ID, 10)
	user.Name = ghUser.Name
	user.Username = ghUser.Login
	user.AvatarURL = ghUser.AvatarURL

	return user, nil
}

func (o *OAuthHandler) handleOAuthUser(
	ctx context.Context,
	unified UnifiedUser,
	oidcConfig *db.OidcProvider,
	linkUserID string,
) (*db.User, error) {
	if unified.ProviderID == "" {
		return nil, fmt.Errorf("no user ID from provider")
	}

	domain, err := email.GetDomain(unified.Email)
	if err != nil {
		return nil, fmt.Errorf("invalid email format")
	}

	// Either static oauth provider or oidc uuid
	providerName := unified.Provider

	// For OIDC, use email domain to find workspace
	if oidcConfig != nil {
		providerForDomain, err := o.cfg.Conn.Q.GetOIDCProviderByDomain(ctx, domain)
		if err != nil || providerForDomain.WorkspaceID != oidcConfig.WorkspaceID {
			return nil, fmt.Errorf("domain not verified for selected provider")
		}
		providerName = oidcConfig.WorkspaceID
	}

	// Generate username
	username, err := util.GenerateUsername(
		unified.Email,
		unified.Username,
		[]string{unified.Name},
	)
	if err != nil || username == "" {
		return nil, fmt.Errorf("no username available from provider")
	}

	var user *db.User
	err = o.cfg.Conn.WithTx(ctx, func(q *db.Queries) error {
		if linkUserID != "" {
			// Linking to an already authenticated user
			existing, err := q.GetOAuthIdentity(ctx, &db.GetOAuthIdentityParams{
				ProviderID: unified.ProviderID,
				Provider:   providerName,
			})
			if err == nil && existing.UserID != linkUserID {
				return fmt.Errorf(
					"this account is already linked to a different user. Delete that account first, then try linking again",
				)
			}

			existingUser, err := q.GetUserByID(ctx, linkUserID)
			if err != nil {
				return fmt.Errorf("link user not found: %w", err)
			}
			user = existingUser
		} else {
			// Check if this OAuth identity is already linked to a user
			existing, err := q.GetOAuthIdentity(ctx, &db.GetOAuthIdentityParams{
				ProviderID: unified.ProviderID,
				Provider:   providerName,
			})
			if err == nil {
				existingUser, err := q.GetUserByID(ctx, existing.UserID)
				if err == nil {
					user = existingUser
				}
			}

			// If not linked yet, try finding by email
			if user == nil {
				// Check SSO enforcement for new logins
				if err := checkSSOEnforced(ctx, o.cfg, unified.Email); err != nil {
					return fmt.Errorf("sso enforcement check failed: %w", err)
				}

				existingUser, err := q.GetUserByEmail(ctx, unified.Email)
				if err == nil {
					user = existingUser
				}
			}

			// If no user exists, check if we can create one
			if user == nil {
				// For OIDC, check JIT provisioning
				if oidcConfig != nil && !oidcConfig.AllowJitProvisioning {
					return fmt.Errorf("JIT provisioning disabled for this workspace")
				}

				// Create new user
				user, err = q.CreateUser(ctx, &db.CreateUserParams{
					Username: username,
					Email:    unified.Email,
					Name:     unified.Name,
					Picture:  &unified.AvatarURL,
				})
				if err != nil {
					return fmt.Errorf("create user: %w", err)
				}

				// Verify email since OAuth provider confirmed it
				if err = q.VerifyUserEmail(ctx, &db.VerifyUserEmailParams{
					UserID: user.ID,
					Email:  unified.Email,
				}); err != nil {
					return fmt.Errorf("verify email: %w", err)
				}

				// Add to workspace for OIDC
				if oidcConfig != nil {
					if err = q.AddWorkspaceMember(ctx, &db.AddWorkspaceMemberParams{
						UserID:      user.ID,
						WorkspaceID: oidcConfig.WorkspaceID,
					}); err != nil {
						return fmt.Errorf("add workspace member: %w", err)
					}
				}
			}
		}

		// Upsert OAuth identity (link if new, update if exists)
		if _, err = q.UpsertOAuthIdentity(ctx, &db.UpsertOAuthIdentityParams{
			ProviderID:       unified.ProviderID,
			Provider:         providerName,
			UserID:           user.ID,
			ProviderEmail:    &unified.Email,
			ProviderUsername: &username,
		}); err != nil {
			return fmt.Errorf("upsert oauth identity: %w", err)
		}

		updateParams := &db.UpdateUserParams{
			UserID:   user.ID,
			Username: &username,
			Picture:  &unified.AvatarURL,
		}
		if unified.Name != "" {
			updateParams.Name = &unified.Name
		}

		// Update user profile with latest OAuth data
		if _, err = q.UpdateUser(ctx, updateParams); err != nil {
			return fmt.Errorf("update user: %w", err)
		}

		return nil
	})

	return user, err
}

// extractOIDCClaims extracts user data from ID token using custom claim mappings.
func extractOIDCClaims(idToken *oidc.IDToken, oidcConfig *db.OidcProvider) (UnifiedUser, error) {
	var allClaims map[string]any
	if err := idToken.Claims(&allClaims); err != nil {
		return UnifiedUser{}, fmt.Errorf("failed to extract claims: %w", err)
	}

	// Helper to get string claim
	getStringClaim := func(claimName string) string {
		if val, ok := allClaims[claimName]; ok {
			if str, ok := val.(string); ok {
				return str
			}
		}
		return ""
	}

	// Helper to get bool claim
	getBoolClaim := func(claimName string) bool {
		if val, ok := allClaims[claimName]; ok {
			if b, ok := val.(bool); ok {
				return b
			}
		}
		return false
	}

	// Set default claims (for Google), override if custom OIDC config exists
	emailClaim, nameClaim, usernameClaim, pictureClaim := "email", "name", "preferred_username", "picture"
	if oidcConfig != nil {
		emailClaim = oidcConfig.EmailClaim
		nameClaim = oidcConfig.NameClaim
		usernameClaim = oidcConfig.UsernameClaim
		pictureClaim = oidcConfig.PictureClaim
	}

	// Extract using determined mappings
	email := getStringClaim(emailClaim)
	name := getStringClaim(nameClaim)
	username := getStringClaim(usernameClaim)
	picture := getStringClaim(pictureClaim)

	// Email verification logic
	emailVerified := getBoolClaim("email_verified")
	if oidcConfig != nil {
		emailVerified = emailVerified || getBoolClaim(oidcConfig.EmailClaim+"_verified")
	}

	if !emailVerified {
		return UnifiedUser{}, fmt.Errorf("email not verified")
	}

	if email == "" {
		return UnifiedUser{}, fmt.Errorf("email claim '%s' not found or empty", emailClaim)
	}

	return UnifiedUser{
		Email:      email,
		Name:       name,
		Username:   username,
		AvatarURL:  picture,
		ProviderID: idToken.Subject,
	}, nil
}
