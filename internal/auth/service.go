package auth

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/mizuchilabs/kagi"
	"github.com/mizuchilabs/kagi/apikey"
	"github.com/mizuchilabs/kagi/backupcode"
	"github.com/mizuchilabs/kagi/dpop"
	"github.com/mizuchilabs/kagi/password"

	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/email"
)

// Service is the kagi authentication engine wired for nokku: the service
// itself plus the pieces the transport adapters need (session authenticator,
// API-key manager, DPoP verifier, password manager, one-time tokens).
type Service struct {
	Kagi          *kagi.Service
	Store         *Store
	Authenticator *kagi.Authenticator
	APIKeys       *apikey.Manager
	DPoP          *dpop.Verifier
	Passwords     *password.Manager
	BackupCodes   *backupcode.Manager
	Tokens        *Tokens
}

// NewService builds the kagi engine for nokku. nonceSecret keys the stateless
// DPoP server nonce (RFC 9449 section 8) and must be shared across instances.
// sso carries the static SSO provider credentials.
func NewService(conn *db.Connection, nonceSecret []byte, sso SSOConfig) (*Service, error) {
	store := NewStore(conn)
	dpopVerifier := dpop.New(dpop.Options{NonceSecret: nonceSecret})

	kagiSvc, err := kagi.New(kagi.Options{
		Store:         store,
		Policy:        ssoPolicy(conn, sso),
		ResolveTenant: resolveTenant,
		DPoP:          dpopVerifier,
		Sessions: kagi.SessionOptions{
			TTL:        24 * time.Hour,
			CookieName: "session",
			Secure:     true,
		},
		Events: kagi.SinkFunc(func(_ context.Context, e kagi.Event) {
			slog.Info("auth event",
				"tenant", e.TenantID,
				"user", e.UserID,
				"method", e.Method,
				"action", e.Action,
				"provider", e.Provider,
			)
		}),
		OnLogin: func(ctx context.Context, _ kagi.TenantID, u kagi.User, m kagi.Method) error {
			row, err := conn.Q.GetUserByID(ctx, u.ID)
			if err != nil || !row.IsActive || !row.EmailVerified {
				return kagi.ErrLoginRejected
			}
			// SSO enforcement applies to every method except the IdP flows
			// themselves (oidc/saml are the enforced path).
			if m != kagi.MethodOIDC && m != kagi.MethodSAML {
				if ssoEnforced(ctx, conn, row.Email) {
					return kagi.ErrLoginRejected
				}
			}
			return nil
		},
	})
	if err != nil {
		return nil, err
	}

	apiKeys, err := apikey.New(kagiSvc, store)
	if err != nil {
		return nil, err
	}

	return &Service{
		Kagi:          kagiSvc,
		Store:         store,
		Authenticator: &kagi.Authenticator{Sessions: kagiSvc.Sessions, DPoP: dpopVerifier},
		APIKeys:       apiKeys,
		DPoP:          dpopVerifier,
		Passwords:     password.New(kagiSvc, password.DefaultParams()),
		BackupCodes:   backupcode.New(kagiSvc),
		Tokens:        NewTokens(conn, 15*time.Minute),
	}, nil
}

// resolveTenant maps a request to a kagi tenant. nokku's users, credentials,
// and sessions are global, so this returns the workspace a request is acting
// in when one is present and an empty tenant otherwise. SSO login routes will
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

// ssoEnforced reports whether the email's domain belongs to a workspace that
// enforces single sign-on.
func ssoEnforced(ctx context.Context, conn *db.Connection, addr string) bool {
	domain, err := email.GetDomain(addr)
	if err != nil {
		return false
	}
	var enforced bool
	if err := conn.WithTx(ctx, func(q *db.Queries) (err error) {
		enforced, err = q.CheckDomainSSOEnforcement(ctx, domain)
		return err
	}); err != nil {
		return false
	}
	return enforced
}
