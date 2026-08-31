package auth

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/mizuchilabs/kagi"
	kagipg "github.com/mizuchilabs/kagi/store/postgres"

	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/email"
)

// deviceSessionTTL is how long an nk device session lasts before the user
// must re-run the browser device flow. Longer than the web session (24h) so a
// daily-driver CLI is not hitting the browser every day, but bounded because
// there is no refresh flow.
const deviceSessionTTL = 7 * 24 * time.Hour

// tokenTTL is the lifetime of one-time email tokens (verify, reset).
const tokenTTL = 15 * time.Minute

// Deps carries everything kagi needs from nokku to build the auth layer.
type Deps struct {
	// Store is the opened kagi store (see OpenStore).
	Store *kagipg.Store
	// Conn is nokku's pool, for the SSO enforcement and provisioning hooks.
	Conn *db.Connection
	// Cache backs SSO flow state, ceremonies, device grants, DPoP replay,
	// and rate limits. Shared with the rest of the app.
	Cache kagi.Cache
	// Email delivers the one-time-link emails kagi composes.
	Email *email.Service
	// BaseURL is the public origin: one-time links, DPoP htu checks, Secure
	// cookies, and the WebAuthn relying-party id.
	BaseURL string
	// Secret is the master secret kagi derives its at-rest keys from: the
	// cipher for SSO client secrets and the SAML SP private key, and the
	// DPoP nonce key. Must be shared across instances.
	Secret []byte
	// Cipher optionally replaces kagi's derived cipher with an external
	// one, e.g. the KMS encryptor. nil keeps the derived secretbox.
	Cipher kagi.Cipher
	// Google and GitHub credentials for the static social providers; empty
	// disables a provider.
	GoogleClientID     string
	GoogleClientSecret string
	GitHubClientID     string
	GitHubClientSecret string
	// Debug adds the frontend dev server to the WebAuthn origins.
	Debug bool
}

// Runtime is the wired auth layer: the mounted kagi handler plus the kagi
// handles nokku code calls directly. It is plain data, not a facade: every
// field is a kagi type used as documented there.
type Runtime struct {
	*kagi.Auth

	// Store is the opened kagi store, for hooks and jobs that run inside
	// the auth layer's own flows.
	Store *kagipg.Store
	// Keys issues and verifies service-account API keys. It is attached to
	// the auth kernel, so the connect interceptor accepts its keys too.
	Keys *kagi.APIKeyManager
	// Account is the account-surface config kagi serves /auth/account with.
	// The Guard is wired here; config attaches OnDelete once billing and
	// storage exist (the pointer is shared with the running handler).
	Account *kagi.AccountConfig
}

// New builds the kagi auth layer for nokku in one Config block: password and
// backup-code login with email round trips, passkeys, Google/GitHub social
// login, per-workspace enterprise OIDC/SAML, the device flow for nk, DPoP for
// daemons, and service-account API keys.
func New(ctx context.Context, d Deps) (*Runtime, error) {
	rt := &Runtime{Store: d.Store}
	// The one-time-token manager backs the mounted email flows; nothing
	// outside kagi's config needs it.
	tokens := kagi.NewTokenManager(d.Store, tokenTTL)
	rt.Account = &kagi.AccountConfig{}

	svc, err := build(d, tokens, rt.Account)
	if err != nil {
		return nil, err
	}
	rt.Auth = svc

	// Attach the API-key verifier without mounting kagi's issue endpoint:
	// service-account keys are issued through the ServiceAccountService RPC.
	rt.Keys, err = kagi.NewAPIKeyManager(svc.Service())
	if err != nil {
		return nil, err
	}

	// The kagi store owns its pool; release it with the application context.
	go func() {
		<-ctx.Done()
		_ = d.Store.Close()
	}()

	return rt, nil
}

// build assembles kagi.New. Split from New so the Runtime can reference the
// handler in the ResolveUser closures: they run per request, after New has
// finished, but kagi builds the handlers eagerly.
func build(
	d Deps,
	tokens *kagi.TokenManager,
	account *kagi.AccountConfig,
) (*kagi.Auth, error) {
	u, err := url.Parse(d.BaseURL)
	if err != nil {
		return nil, err
	}

	return kagi.New(kagi.Config{
		Store:   d.Store,
		Cache:   d.Cache,
		BaseURL: d.BaseURL,
		Secret:  d.Secret,
		Cipher:  d.Cipher,
		// nokku's users, credentials, and sessions are global; the workspace
		// a request acts in is the effective tenant.
		ResolveTenant: resolveTenant,
		Account:       account,

		// Account state (active, verified) and SSO enforcement gate every
		// session issuance.
		EnforceAccountState: true,
		// Static social providers seed into kagi's storage at boot, so
		// every provider resolves from storage and no ResolveProvider hook
		// is needed. Idempotent: unchanged rows are not rewritten.
		SSOSeed: socialProviders(d),
		// Enterprise SSO logins run under the provider's workspace (the
		// provider id doubles as the workspace id) and join it: membership
		// is nokku data; everything else about the login is kagi's. Social
		// and password logins run under the global tenant and join nothing.
		OnLogin: func(ctx context.Context, t kagi.TenantID, u kagi.User, _ kagi.Method) error {
			if t == "" {
				return nil
			}
			return d.Conn.WithTx(ctx, func(q *db.Queries) error {
				return q.AddWorkspaceMember(ctx, &db.AddWorkspaceMemberParams{
					UserID:      u.ID,
					WorkspaceID: string(t),
				})
			})
		},
		Events: slogSink(),

		Flows: &kagi.Flows{
			ValidateEmail: email.Verify,
			Tokens:        tokens,
			Mailer:        kagiMailer{email: d.Email},
		},

		Passkeys: &kagi.PasskeyConfig{
			RPID:          u.Hostname(),
			RPDisplayName: "Nokku",
			RPOrigins:     rpOrigins(d),
			Signup:        true,
		},

		OIDC: &kagi.OIDCConfig{
			ErrorRedirect: d.BaseURL + "/auth-error",
		},

		OAuth2: &kagi.OAuth2Config{
			ErrorRedirect: d.BaseURL + "/auth-error",
		},

		SAML: &kagi.SAMLConfig{
			ErrorRedirect: d.BaseURL + "/auth-error",
			AcsURL:        d.BaseURL + "/saml/acs",
			SPEntityID:    d.BaseURL + "/saml/metadata",
		},

		Device: &kagi.DeviceConfig{
			VerificationURI: d.BaseURL + "/device",
			SessionTTL:      deviceSessionTTL,
			Kind:            ActorTypeDevice,
		},

		DPoP: &kagi.DPoPConfig{},
	})
}

// socialProviders builds the static social login providers from the
// environment credentials. They seed into kagi's storage at boot
// (Config.SSOSeed), so they resolve like any stored provider. A provider
// without credentials is omitted, which disables it.
func socialProviders(d Deps) []kagi.SSOProvider {
	var out []kagi.SSOProvider
	if d.GoogleClientID != "" && d.GoogleClientSecret != "" {
		p := kagi.OIDCGoogle(d.GoogleClientID, d.GoogleClientSecret)
		p.JITProvisioning = true
		out = append(out, kagi.SSOProvider{
			TenantID:   "",
			ProviderID: "google",
			Method:     kagi.MethodOIDC,
			Name:       "Google",
			Enabled:    true,
			OIDC:       &p,
		})
	}
	if d.GitHubClientID != "" && d.GitHubClientSecret != "" {
		p := kagi.OAuth2GitHub(d.GitHubClientID, d.GitHubClientSecret)
		p.JITProvisioning = true
		out = append(out, kagi.SSOProvider{
			TenantID:   "",
			ProviderID: "github",
			Method:     kagi.MethodOAuth2,
			Name:       "GitHub",
			Enabled:    true,
			OAuth2:     &p,
		})
	}
	return out
}

// rpOrigins returns the WebAuthn relying-party origins: the app URL plus the
// frontend dev server in debug mode.
func rpOrigins(d Deps) []string {
	origins := []string{d.BaseURL}
	if d.Debug {
		origins = append(origins, "http://localhost:5173")
	}
	return origins
}

// slogSink is the default auth event sink used until the audit service is
// wired in; it never drops the event, just emits it to the log.
func slogSink() kagi.Sink {
	return kagi.SinkFunc(func(_ context.Context, e kagi.Event) {
		slog.Info("auth event",
			"tenant", e.TenantID,
			"user", e.UserID,
			"method", e.Method,
			"action", e.Action,
			"provider", e.Provider,
		)
	})
}

// resolveTenant maps a request to a kagi tenant. nokku's users, credentials,
// and sessions are global, so this returns the workspace a request is acting
// in when one is present and an empty tenant otherwise. SSO login routes
// resolve the workspace explicitly from the request (domain or parameter)
// before calling into kagi's provider handlers.
func resolveTenant(r *http.Request) (kagi.TenantID, error) {
	if ws := r.URL.Query().Get("workspace_id"); ws != "" {
		return kagi.TenantID(ws), nil
	}
	if ws := r.Header.Get("X-Nokku-Workspace"); ws != "" {
		return kagi.TenantID(ws), nil
	}
	return "", nil
}
