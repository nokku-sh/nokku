package iam

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/cache"
	"github.com/nokku-sh/nokku/core/internal/crypto"
	"github.com/nokku-sh/nokku/core/internal/db"
)

const oidcCallbackPath = "/oidc/callback"

type oidcFlow struct {
	svc       *Service
	state     *sealed[authorizeState]
	providers *cache.Local[*oidc.Provider]
	// tests holds finished test sign-ins until the settings page reads them.
	tests *cache.Memory
}

type authorizeState struct {
	ProviderID   string  `json:"provider_id"`
	Nonce        string  `json:"nonce"`
	PKCEVerifier string  `json:"pkce_verifier"`
	ReturnTo     string  `json:"return_to,omitempty"`
	LinkUserID   string  `json:"link_user_id,omitempty"`
	Tester       *tester `json:"tester,omitempty"`
}

// oidcIdentity is what the provider said about the person.
type oidcIdentity struct {
	ProviderID      string
	Subject         string
	Email           string
	Name            string
	Picture         string
	JITProvisioning bool
	// EmailUnverified is set when the provider says so. A missing claim counts as verified, Entra never sends it.
	EmailUnverified bool
	// LinkUserID skips the email lookup and links to that signed-in user.
	LinkUserID string
}

func newOIDCFlow(svc *Service) *oidcFlow {
	return &oidcFlow{
		svc:       svc,
		state:     &sealed[authorizeState]{svc: svc, cookie: flowCookieName, use: "oidc", ttl: flowStateTTL},
		providers: cache.NewLocal[*oidc.Provider](providerCacheTTL),
		tests:     cache.NewMemory(testEntries),
	}
}

// Login signs in, or with link=true links the identity to the signed-in user.
func (h *oidcFlow) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cfg, err := h.svc.loginProvider(ctx, r.URL.Query().Get("provider"))
	if err != nil {
		fail(w, r, "provider not configured")
		return
	}
	// A refused link must not go on as a sign-in, that could make a second account.
	linkUserID, err := linkUserIDFor(ctx, r)
	if err != nil {
		fail(w, r, "link refused")
		return
	}
	provider, err := h.discover(ctx, cfg.OIDC.IssuerURL)
	if err != nil {
		slog.Warn("sso login start failed", "error", err, "provider", cfg.ProviderID)
		fail(w, r, "provider unavailable")
		return
	}
	h.start(w, r, cfg, provider, authorizeState{
		ReturnTo:   safeReturnTo(r.URL.Query().Get("return_to")),
		LinkUserID: linkUserID,
	})
}

// start seals the flow state and sends the browser to the provider.
func (h *oidcFlow) start(
	w http.ResponseWriter,
	r *http.Request,
	cfg *SSOProvider,
	provider *oidc.Provider,
	st authorizeState,
) {
	st.ProviderID = cfg.ProviderID
	st.Nonce = crypto.RandomString(32)
	st.PKCEVerifier = oauth2.GenerateVerifier()
	key, err := h.state.put(w, st)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	conf := h.oauth2Config(r.Context(), &cfg.OIDC, provider)
	// #nosec G710 -- redirects to the provider authorization endpoint from its configuration.
	http.Redirect(
		w, r,
		conf.AuthCodeURL(key, oidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.PKCEVerifier)),
		http.StatusTemporaryRedirect,
	)
}

// Callback checks that the state names the flow this browser started, or the answer belongs to someone else.
func (h *oidcFlow) Callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	st, flowID, err := h.state.take(r)
	if err != nil || subtle.ConstantTimeCompare([]byte(flowID), []byte(q.Get("state"))) != 1 {
		if q.Get("error") != "" {
			fail(w, r, "login canceled")
			return
		}
		fail(w, r, "invalid or expired login")
		return
	}
	if st.Tester != nil {
		h.finishTestFlow(w, r, flowID, st)
		return
	}
	if q.Get("error") != "" {
		fail(w, r, "login canceled")
		return
	}
	cfg, err := h.svc.loginProvider(r.Context(), st.ProviderID)
	if err != nil {
		fail(w, r, "provider not configured")
		return
	}
	idToken, claims, _, err := h.verify(r.Context(), q, cfg, st)
	if err != nil {
		slog.Warn("oidc callback failed", "error", err, "provider", cfg.ProviderID)
		fail(w, r, "login failed")
		return
	}

	id := identityFrom(cfg, idToken, claims)
	id.LinkUserID = st.LinkUserID
	u, err := h.resolve(r.Context(), id)
	if err != nil {
		h.svc.record(r.Context(), event{
			Action: actionLoginDenied, Method: MethodOIDC, UserID: id.LinkUserID, Email: id.Email, Detail: err.Error(),
		})
		slog.Warn("sso login rejected", "error", err, "provider", cfg.ProviderID)
		switch {
		case errors.Is(err, errEmailUnverified):
			fail(w, r, "email not verified")
		case errors.Is(err, errOwnerLink):
			fail(w, r, "owner link required")
		default:
			fail(w, r, "identity rejected")
		}
		return
	}
	cookie, err := h.svc.completeLogin(r.Context(), u, MethodOIDC)
	if err != nil {
		fail(w, r, "login refused")
		return
	}
	h.svc.spendFlow(r.Context(), flowID)
	http.SetCookie(w, h.svc.newCookie(flowCookieName, "", time.Unix(0, 0)))
	http.SetCookie(w, cookie)
	if c := h.svc.RememberDevice(r.Context(), r.Header, r.RemoteAddr, u); c != nil {
		http.SetCookie(w, c)
	}
	// Re-sanitize, the value round-tripped through the cookie.
	returnTo := safeReturnTo(st.ReturnTo)
	if returnTo == "" {
		returnTo = "/"
	}
	// #nosec G710 -- safeReturnTo only lets same-origin absolute paths through.
	http.Redirect(w, r, returnTo, http.StatusSeeOther)
}

// verify checks the provider's answer to an authorization that went through. The step says where it broke, for a test to show.
func (h *oidcFlow) verify(
	ctx context.Context,
	q url.Values,
	cfg *SSOProvider,
	st authorizeState,
) (*oidc.IDToken, map[string]any, nokkuv1.SSOTestStep, error) {
	ctx = h.svc.providerContext(ctx)
	provider, err := h.discover(ctx, cfg.OIDC.IssuerURL)
	if err != nil {
		return nil, nil, nokkuv1.SSOTestStep_SSO_TEST_STEP_DISCOVERY, err
	}
	// RFC 9207 mix-up attack protection.
	if iss := q.Get("iss"); iss != "" &&
		!strings.EqualFold(strings.TrimSuffix(iss, "/"), strings.TrimSuffix(cfg.OIDC.IssuerURL, "/")) {
		return nil, nil, nokkuv1.SSOTestStep_SSO_TEST_STEP_AUTHORIZE,
			fmt.Errorf("the answer came from issuer %q, not %q", iss, cfg.OIDC.IssuerURL)
	}
	token, err := h.oauth2Config(ctx, &cfg.OIDC, provider).Exchange(
		ctx,
		q.Get("code"),
		oauth2.VerifierOption(st.PKCEVerifier),
	)
	if err != nil {
		return nil, nil, nokkuv1.SSOTestStep_SSO_TEST_STEP_TOKEN, err
	}
	idTokenFailed := func(err error) (*oidc.IDToken, map[string]any, nokkuv1.SSOTestStep, error) {
		return nil, nil, nokkuv1.SSOTestStep_SSO_TEST_STEP_ID_TOKEN, err
	}
	rawIDToken, _ := token.Extra("id_token").(string)
	idToken, err := provider.Verifier(&oidc.Config{ClientID: cfg.OIDC.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		return idTokenFailed(err)
	}
	// at_hash is optional in the code flow and Keycloak omits it.
	if idToken.AccessTokenHash != "" {
		if err := idToken.VerifyAccessToken(token.AccessToken); err != nil {
			return idTokenFailed(err)
		}
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return idTokenFailed(err)
	}
	nonce, _ := claims["nonce"].(string)
	if subtle.ConstantTimeCompare([]byte(nonce), []byte(st.Nonce)) != 1 {
		return idTokenFailed(errors.New("the nonce does not match the one this sign-in sent"))
	}
	return idToken, claims, nokkuv1.SSOTestStep_SSO_TEST_STEP_UNSPECIFIED, nil
}

func identityFrom(cfg *SSOProvider, idToken *oidc.IDToken, claims map[string]any) oidcIdentity {
	return oidcIdentity{
		ProviderID:      cfg.ProviderID,
		Subject:         idToken.Subject,
		Email:           claimString(claims, "email"),
		Name:            claimString(claims, "name"),
		Picture:         claimString(claims, "picture"),
		JITProvisioning: cfg.OIDC.JITProvisioning,
		EmailUnverified: claimIsFalse(claims["email_verified"]),
	}
}

// resolve trusts a matching email and may create the account, the workspace owner configured the provider.
// The owner is never matched by email. A provider user who can pick their address would take the workspace.
func (h *oidcFlow) resolve(ctx context.Context, id oidcIdentity) (*db.User, error) {
	var u *db.User
	created := false
	err := h.svc.conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		u, created, err = h.resolveIn(ctx, q, id)
		return err
	})
	if err != nil {
		return nil, mapNotFound(err)
	}
	if created {
		h.svc.record(ctx, event{
			Action: actionUserCreated, Kind: actor.KindUser, Method: MethodOIDC, UserID: u.ID, Email: u.Email,
		})
	}
	return u, nil
}

// resolveIn runs in the caller's tx, so a test sign-in can make the same decision and roll it back.
func (h *oidcFlow) resolveIn(ctx context.Context, q *db.Queries, id oidcIdentity) (*db.User, bool, error) {
	cred, err := q.FindCredentialBySubject(ctx, &db.FindCredentialBySubjectParams{
		Type: string(MethodOIDC), Provider: id.ProviderID, Subject: id.Subject,
	})
	switch {
	case err == nil:
		if id.LinkUserID != "" && cred.UserID != id.LinkUserID {
			return nil, false, errIdentityLinked
		}
		u, err := q.GetUser(ctx, cred.UserID)
		if err != nil {
			return nil, false, err
		}
		return u, false, q.TouchCredential(ctx, cred.ID)
	case !errors.Is(err, pgx.ErrNoRows):
		return nil, false, err
	}

	var u *db.User
	created := false
	switch {
	case id.LinkUserID != "":
		u, err = q.GetUser(ctx, id.LinkUserID)
	case id.Email == "":
		return nil, false, errIdentityRejected
	case id.EmailUnverified:
		return nil, false, errEmailUnverified
	default:
		email := normalizeEmail(id.Email)
		u, err = q.GetUserByEmail(ctx, email)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			if !id.JITProvisioning {
				return nil, false, errIdentityRejected
			}
			u, err = h.svc.createUser(ctx, q, db.CreateUserWithIDParams{
				Email: email, Name: id.Name, Picture: nonEmpty(id.Picture),
			}, "")
			created = err == nil
		case err == nil && u.Role == nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER:
			return nil, false, errOwnerLink
		case err == nil && id.Name != "" && u.Name != id.Name:
			// The provider owns the name.
			u, err = q.UpdateUser(ctx, &db.UpdateUserParams{ID: u.ID, Name: &id.Name})
		}
	}
	if err != nil {
		return nil, false, err
	}
	return u, created, link(ctx, q, id, u.ID)
}

func link(ctx context.Context, q *db.Queries, id oidcIdentity, userID string) error {
	_, err := q.UpsertCredential(ctx, &db.UpsertCredentialParams{
		ID:       actor.WorkspaceIDFromContext(ctx) + ":" + id.ProviderID + ":" + id.Subject,
		UserID:   userID,
		Type:     string(MethodOIDC),
		Provider: id.ProviderID,
		Subject:  id.Subject,
		Data:     []byte{},
	})
	if errors.Is(err, pgx.ErrNoRows) || db.IsUniqueViolation(err) {
		return errIdentityLinked
	}
	return err
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

func (h *oidcFlow) oauth2Config(ctx context.Context, cfg *OIDCProvider, provider *oidc.Provider) *oauth2.Config {
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
		RedirectURL:  RedirectURI(ctx),
		Scopes:       scopes,
	}
}

// RedirectURI is what the owner registers with every provider of the workspace.
func RedirectURI(ctx context.Context) string {
	return baseURL(ctx) + oidcCallbackPath
}

func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
