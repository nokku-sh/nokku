package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"

	"github.com/nokku-sh/nokku/internal/authn"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/email"
	"github.com/nokku-sh/nokku/internal/meta"
	"github.com/nokku-sh/nokku/internal/util"
)

// OAuthSession represents the temporary state stored in cache during the flow.
type OAuthSession struct {
	ProviderID   string `json:"provider_id"`
	Nonce        string `json:"nonce,omitempty"`
	PKCEVerifier string `json:"pkce_verifier,omitempty"`
	LinkUserID   string `json:"link_user_id,omitempty"`
}

// OAuthHandler serves the public OAuth2 flow (github).
type OAuthHandler struct {
	cfg *config.Config
}

func NewOAuthHandler(cfg *config.Config) *OAuthHandler {
	return &OAuthHandler{cfg: cfg}
}

// startOAuthSession persists the session server-side and drops the CSRF state
// cookie. The state binds the browser to the cached session for the callback.
func startOAuthSession(
	cfg *config.Config,
	w http.ResponseWriter,
	r *http.Request,
	state string,
	session OAuthSession,
) error {
	data, err := json.Marshal(session)
	if err != nil {
		return err
	}
	if err := cfg.Cache.Set(r.Context(), "oauth_state."+state, data, 10*time.Minute); err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		MaxAge:   600, // 10 minutes
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// loadOAuthSession validates the CSRF state cookie against the query
// parameter, consumes the server-side session, and returns it. On failure it
// returns the error code to surface in the redirect.
func loadOAuthSession(
	cfg *config.Config,
	w http.ResponseWriter,
	r *http.Request,
) (*OAuthSession, string) {
	stateCookie, err := r.Cookie("oauth_state")
	stateQuery := r.URL.Query().Get("state")
	if err != nil || stateCookie.Value != stateQuery {
		return nil, "invalid_state"
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		MaxAge:   -1,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	data, err := cfg.Cache.Get(r.Context(), "oauth_state."+stateQuery)
	if err != nil || data == nil {
		return nil, "session_expired"
	}
	_ = cfg.Cache.Delete(r.Context(), "oauth_state."+stateQuery)

	var session OAuthSession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, "invalid_session"
	}
	return &session, ""
}

// linkUserIDFromRequest returns the authenticated user's ID when the login is
// a link request initiated from the app, or "" otherwise.
func linkUserIDFromRequest(cfg *config.Config, r *http.Request) string {
	if r.URL.Query().Get("link") != "true" {
		return ""
	}
	tokenStr := authn.GetAccessToken(r.Header)
	if tokenStr == "" {
		return ""
	}
	claims, err := cfg.Authn.VerifyToken(tokenStr)
	if err != nil {
		return ""
	}
	return claims.UserID
}

// authRedirect redirects back to the app after a login callback. 302, not
// 307. Callbacks arrive as POSTs and the SPA has no form action on the
// root. A preserved POST would land on a 405 and silently drop the result.
func authRedirect(w http.ResponseWriter, r *http.Request, base string) {
	http.Redirect(w, r, base, http.StatusFound)
}

// authErrorRedirect redirects to the frontend auth-error page with a
// machine-readable error code.
func authErrorRedirect(w http.ResponseWriter, r *http.Request, base string, code string) {
	http.Redirect(w, r, base+"/auth-error?error="+code, http.StatusFound)
}

// redirectFailure redirects with a generic error code, mapping SSO
// enforcement to its own code so the frontend can explain the failure.
func redirectFailure(w http.ResponseWriter, r *http.Request, redirect string, err error) {
	code := "user_failed"
	if errors.Is(err, ErrSSORequired) {
		code = "sso_required"
	}
	authErrorRedirect(w, r, redirect, code)
}

// completeLogin signs the user in: attributes the audit event, issues the
// session cookies, and redirects to the app.
func completeLogin(
	ctx context.Context,
	cfg *config.Config,
	w http.ResponseWriter,
	r *http.Request,
	user *db.User,
) {
	if a := meta.AuditStateFromContext(ctx); a != nil {
		a.UserID = user.ID
	}
	cfg.Authn.AccessCookie(ctx, w.Header(), user)
	cfg.Authn.RefreshCookie(ctx, w.Header(), user)
	syncWebDevice(ctx, cfg, r.Header, w.Header(), r.RemoteAddr, user)
	authRedirect(w, r, cfg.FullURL())
}

func (o *OAuthHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	state, err := crypto.RandomString(32)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Internal error")
		return
	}

	session := OAuthSession{
		ProviderID: "github",
		LinkUserID: linkUserIDFromRequest(o.cfg, r),
	}

	conf := &oauth2.Config{
		ClientID:     o.cfg.GitHubClientID,
		ClientSecret: o.cfg.GitHubClientSecret,
		RedirectURL:  o.cfg.FullURL() + "/oauth/callback",
		Scopes:       []string{"user:email", "read:user"},
		Endpoint:     github.Endpoint,
	}

	if err := startOAuthSession(o.cfg, w, r, state, session); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Internal error")
		return
	}
	http.Redirect(w, r, conf.AuthCodeURL(state), http.StatusTemporaryRedirect)
}

func (o *OAuthHandler) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	redirect := o.cfg.FullURL()

	session, code := loadOAuthSession(o.cfg, w, r)
	if code != "" {
		authErrorRedirect(w, r, redirect, code)
		return
	}

	conf := &oauth2.Config{
		ClientID:     o.cfg.GitHubClientID,
		ClientSecret: o.cfg.GitHubClientSecret,
		RedirectURL:  o.cfg.FullURL() + "/oauth/callback",
		Endpoint:     github.Endpoint,
	}
	token, err := conf.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		authErrorRedirect(w, r, redirect, "token_exchange_failed")
		return
	}

	profile, providerID, err := fetchGitHubUser(r.Context(), token)
	if err != nil {
		authErrorRedirect(w, r, redirect, "github_fetch_failed")
		return
	}

	dbUser, err := handleOAuthUser(
		r.Context(),
		o.cfg,
		profile,
		providerID,
		"github",
		nil,
		session.LinkUserID,
	)
	if err != nil {
		redirectFailure(w, r, redirect, err)
		return
	}
	completeLogin(r.Context(), o.cfg, w, r, dbUser)
}

// fetchGitHubUser resolves the authenticated GitHub user's profile and the
// provider's subject identifier.
func fetchGitHubUser(ctx context.Context, token *oauth2.Token) (*db.User, string, error) {
	client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()

	var ghUser struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ghUser); err != nil {
		return nil, "", err
	}

	reqEmails, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"https://api.github.com/user/emails",
		nil,
	)
	if err != nil {
		return nil, "", err
	}
	respEmails, err := client.Do(reqEmails)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = respEmails.Body.Close() }()

	var emailAddr string
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(respEmails.Body).Decode(&emails); err == nil {
		for _, e := range emails {
			if e.Primary && e.Verified {
				emailAddr = e.Email
				break
			}
		}
	}
	if emailAddr == "" {
		return nil, "", fmt.Errorf("no verified primary email found on github")
	}

	username, err := util.GenerateUsername(emailAddr, ghUser.Login, []string{ghUser.Name})
	if err != nil || username == "" {
		return nil, "", fmt.Errorf("no username available from provider")
	}

	return &db.User{
		Name:     ghUser.Name,
		Username: username,
		Email:    emailAddr,
		Picture:  &ghUser.AvatarURL,
	}, strconv.FormatInt(ghUser.ID, 10), nil
}

// handleOAuthUser turns a verified provider identity into a local user, either
// by linking it to the currently authenticated user or by resolving the
// account behind a login. profile holds the provider-attested profile fields,
// providerID the provider's subject identifier, and provider the provider
// name (workspace ID for enterprise OIDC).
func handleOAuthUser(
	ctx context.Context,
	cfg *config.Config,
	profile *db.User,
	providerID, provider string,
	oidcConfig *db.OidcProvider,
	linkUserID string,
) (*db.User, error) {
	if providerID == "" {
		return nil, fmt.Errorf("no user ID from provider")
	}

	// Linking is a consumer feature for public providers. Workspace identities
	// are owned by the organization and only ever arrive through a login
	// (federation or JIT provisioning), never by user linking.
	if linkUserID != "" && oidcConfig != nil {
		return nil, fmt.Errorf("workspace identities cannot be linked to an existing account")
	}

	domain, err := email.GetDomain(profile.Email)
	if err != nil {
		return nil, fmt.Errorf("invalid email format")
	}

	// Enterprise identities are namespaced by workspace so identities from
	// different organizations can never collide. The user's email domain must
	// be a verified domain of the provider's workspace: that is what allows
	// an organization to route its employees through its own IdP.
	if oidcConfig != nil {
		if provider, err = oidcNamespace(ctx, cfg, oidcConfig, domain); err != nil {
			return nil, err
		}
	}

	// Social logins (github/google) are subject to workspace SSO enforcement
	// for new and returning users alike. Logging in through the workspace IdP
	// itself is the enforced flow, and linking is an authenticated user action.
	if linkUserID == "" && oidcConfig == nil {
		if err := checkSSOEnforced(ctx, cfg, profile.Email); err != nil {
			return nil, err
		}
	}

	var user *db.User
	err = cfg.Conn.WithTx(ctx, func(q *db.Queries) error {
		var err error
		if linkUserID != "" {
			user, err = linkIdentity(ctx, q, providerID, provider, linkUserID)
		} else {
			user, err = loginUser(ctx, q, profile, providerID, provider, oidcConfig)
		}
		if err != nil {
			return err
		}

		// Attach or refresh the link between the provider identity and the
		// resolved account.
		if _, err := q.UpsertUserIdentity(ctx, &db.UpsertUserIdentityParams{
			ProviderID:       providerID,
			Provider:         provider,
			UserID:           user.ID,
			ProviderEmail:    &profile.Email,
			ProviderUsername: &profile.Username,
			Protocol:         identityProtocol(provider),
		}); err != nil {
			return fmt.Errorf("upsert oauth identity: %w", err)
		}

		user, err = finalizeEnterpriseLogin(ctx, q, user, profile, oidcConfig)
		return err
	})

	return user, err
}

// identityProtocol classifies the identity namespace: public providers
// (github, google) are plain OAuth, everything else is enterprise OIDC.
func identityProtocol(provider string) string {
	if provider == "github" || provider == "google" {
		return "oauth"
	}
	return "oidc"
}

// linkIdentity resolves the account for a link request, rejecting identities
// that are already owned by somebody else.
func linkIdentity(
	ctx context.Context,
	q *db.Queries,
	providerID, provider, linkUserID string,
) (*db.User, error) {
	identity, err := q.GetUserIdentity(ctx, &db.GetUserIdentityParams{
		ProviderID: providerID,
		Provider:   provider,
	})
	switch {
	case err == nil:
		if identity.UserID != linkUserID {
			return nil, fmt.Errorf(
				"this account is already linked to a different user. Delete that account first, then try linking again",
			)
		}
	case !errors.Is(err, pgx.ErrNoRows):
		return nil, fmt.Errorf("get oauth identity: %w", err)
	}

	user, err := q.GetUserByID(ctx, linkUserID)
	if err != nil {
		return nil, fmt.Errorf("link user not found: %w", err)
	}
	return user, nil
}

// loginUser resolves the account behind an SSO login. A linked identity wins,
// otherwise the provider-verified email federates onto an existing account,
// otherwise a new user is provisioned (if the workspace allows it).
func loginUser(
	ctx context.Context,
	q *db.Queries,
	profile *db.User,
	providerID, provider string,
	oidcConfig *db.OidcProvider,
) (*db.User, error) {
	identity, err := q.GetUserIdentity(ctx, &db.GetUserIdentityParams{
		ProviderID: providerID,
		Provider:   provider,
	})
	switch {
	case err == nil:
		user, err := q.GetUserByID(ctx, identity.UserID)
		if err != nil {
			return nil, fmt.Errorf("get user: %w", err)
		}
		return user, nil
	case !errors.Is(err, pgx.ErrNoRows):
		return nil, fmt.Errorf("get oauth identity: %w", err)
	}

	// No identity yet: federate onto the account with the same verified email
	// and mark it verified, since the provider attested ownership.
	user, err := q.GetUserByEmail(ctx, profile.Email)
	if err == nil {
		if err := q.VerifyUserEmail(ctx, &db.VerifyUserEmailParams{
			UserID: user.ID,
			Email:  profile.Email,
		}); err != nil {
			return nil, fmt.Errorf("verify email: %w", err)
		}
		return user, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("get user by email: %w", err)
	}

	return provisionUser(ctx, q, profile, oidcConfig)
}

// provisionUser creates the account for a first-time SSO login. When two
// first logins race on the same email, one wins the insert and the other
// proceeds with the winner's account.
func provisionUser(
	ctx context.Context,
	q *db.Queries,
	profile *db.User,
	oidcConfig *db.OidcProvider,
) (*db.User, error) {
	if oidcConfig != nil && !oidcConfig.AllowJitProvisioning {
		return nil, fmt.Errorf("user provisioning is disabled for this workspace")
	}

	user, err := q.CreateOAuthUser(ctx, &db.CreateOAuthUserParams{
		Username: profile.Username,
		Email:    profile.Email,
		Name:     profile.Name,
		Picture:  profile.Picture,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		// ON CONFLICT DO NOTHING returns no row: a concurrent login created
		// the account first.
		user, err = q.GetUserByEmail(ctx, profile.Email)
	}
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}

	if err := q.VerifyUserEmail(ctx, &db.VerifyUserEmailParams{
		UserID: user.ID,
		Email:  profile.Email,
	}); err != nil {
		return nil, fmt.Errorf("verify email: %w", err)
	}
	return user, nil
}
