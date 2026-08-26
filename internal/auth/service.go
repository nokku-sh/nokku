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
	"github.com/mizuchilabs/kagi/tokens"

	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/email"
)

// Service is the kagi authentication engine wired for nokku. It exposes the
// kagi service itself (for the provider handlers and middleware) plus a
// nokku-shaped facade: users and credentials are global, so the kagi tenant
// parameter is elided from every method here. Only machine identities
// (service accounts, daemons) are workspace-scoped, and those methods take an
// explicit workspace id.
type Service struct {
	Kagi        *kagi.Service
	Resolvers   Resolvers
	store       *Store
	apiKeys     *apikey.Manager
	dpop        *dpop.Verifier
	passwords   *password.Manager
	backupCodes *backupcode.Manager
	tokens      *tokens.Manager
}

// NewService builds the kagi engine for nokku. nonceSecret keys the stateless
// DPoP server nonce (RFC 9449 section 8) and must be shared across instances.
// sso carries the static SSO provider credentials.
func NewService(conn *db.Connection, nonceSecret []byte, sso SSOConfig) (*Service, error) {
	store := NewStore(conn)
	dpopVerifier := dpop.New(dpop.Options{NonceSecret: nonceSecret})

	kagiSvc, err := kagi.New(kagi.Options{
		Store:         store,
		ResolveTenant: resolveTenant,
		DPoP:          dpopVerifier,
		Sessions: kagi.SessionOptions{
			TTL:        24 * time.Hour,
			CookieName: "session",
			Secure:     true,
		},
		Events: slogSink(),
		OnLogin: func(ctx context.Context, _ kagi.TenantID, u kagi.User, m kagi.Method) error {
			// SSO enforcement applies to every method except the IdP flows
			// themselves (oidc/saml are the enforced path). Account state
			// (active, verified) is enforced centrally via
			// EnforceAccountState; this hook only knows the email domain.
			if m != kagi.MethodOIDC && m != kagi.MethodSAML {
				if ssoEnforced(ctx, conn, u.Email) {
					return kagi.ErrSSORequired
				}
			}
			return nil
		},
		EnforceAccountState: true,
	})
	if err != nil {
		return nil, err
	}

	apiKeys, err := apikey.New(kagiSvc, store)
	if err != nil {
		return nil, err
	}

	return &Service{
		Kagi:        kagiSvc,
		Resolvers:   NewResolvers(conn, sso),
		store:       store,
		apiKeys:     apiKeys,
		dpop:        dpopVerifier,
		passwords:   password.New(kagiSvc, password.DefaultParams()),
		backupCodes: backupcode.New(kagiSvc),
		tokens:      tokens.New(NewTokenStore(conn), 15*time.Minute),
	}, nil
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

// SetEventSink wires the kagi auth sink to the audit service. The audit
// service is constructed after auth (it needs billing), so it is attached
// once both exist. It must be called before the server starts serving.
func (s *Service) SetEventSink(sink kagi.Sink) {
	if sink == nil {
		return
	}
	s.Kagi.Events = sink
}

// Authenticator returns a session authenticator wired to the kagi service.
func (s *Service) Authenticator() *kagi.Authenticator {
	return s.Kagi.Authenticator()
}

// APIKeys returns the API-key manager, for the connectrpc authn interceptor.
func (s *Service) APIKeys() *apikey.Manager {
	return s.apiKeys
}

// DPoP returns the DPoP proof verifier, for handlers that verify a proof
// outside the connectrpc interceptor (e.g. daemon enrollment).
func (s *Service) DPoP() *dpop.Verifier {
	return s.dpop
}

// Tokens returns the one-time-token manager, for the kagi server package's
// email verification and password-reset flows.
func (s *Service) Tokens() *tokens.Manager {
	return s.tokens
}

// --- Passwords (global users) -------------------------------------------------

func (s *Service) CheckPassword(ctx context.Context, userID, pw string) error {
	return s.passwords.CheckPassword(ctx, "", userID, pw)
}

func (s *Service) HasPassword(ctx context.Context, userID string) (bool, error) {
	return s.passwords.HasPassword(ctx, "", userID)
}

func (s *Service) SetPassword(ctx context.Context, userID, pw string) error {
	return s.passwords.SetPassword(ctx, "", userID, pw)
}

func (s *Service) DeletePassword(ctx context.Context, userID string) error {
	return s.passwords.DeletePassword(ctx, "", userID)
}

func (s *Service) Register(ctx context.Context, email, name, pw string) (kagi.User, error) {
	return s.passwords.Register(ctx, "", email, name, pw)
}

// --- Backup codes (global users) ----------------------------------------------

func (s *Service) ConsumeBackupCode(ctx context.Context, userID, code string) (kagi.User, error) {
	return s.backupCodes.Consume(ctx, "", userID, code)
}

func (s *Service) GenerateBackupCodes(ctx context.Context, userID string, n int) ([]string, error) {
	return s.backupCodes.GenerateCodes(ctx, "", userID, n)
}

func (s *Service) ListBackupCodes(ctx context.Context, userID string) ([]kagi.Credential, error) {
	return s.backupCodes.List(ctx, "", userID)
}

func (s *Service) DeleteBackupCodes(ctx context.Context, userID string) error {
	return s.backupCodes.Delete(ctx, "", userID)
}

// --- Credentials (global users) ------------------------------------------------

func (s *Service) ListCredentials(
	ctx context.Context,
	userID string,
	typ kagi.Method,
) ([]kagi.Credential, error) {
	return s.store.ListCredentials(ctx, "", userID, typ)
}

func (s *Service) GetCredential(ctx context.Context, userID, id string) (kagi.Credential, error) {
	return s.store.GetCredential(ctx, "", userID, id)
}

func (s *Service) PutCredential(ctx context.Context, c kagi.Credential) error {
	return s.store.PutCredential(ctx, "", c)
}

func (s *Service) DeleteCredential(ctx context.Context, userID, id string) error {
	return s.store.DeleteCredential(ctx, "", userID, id)
}

func (s *Service) GetUser(ctx context.Context, userID string) (kagi.User, error) {
	return s.store.GetUser(ctx, "", userID)
}

func (s *Service) GetUserByEmail(ctx context.Context, email string) (kagi.User, error) {
	return s.store.GetUserByEmail(ctx, "", email)
}

func (s *Service) CreateUser(ctx context.Context, u kagi.User) (kagi.User, error) {
	return s.store.CreateUser(ctx, "", u)
}

func (s *Service) DeleteProviderCredentials(
	ctx context.Context,
	provider string,
	typ kagi.Method,
) error {
	return s.store.DeleteProviderCredentials(ctx, provider, typ)
}

// --- One-time tokens -----------------------------------------------------------

func (s *Service) IssueToken(
	ctx context.Context,
	userID string,
	purpose tokens.Purpose,
) (string, error) {
	return s.tokens.Issue(ctx, userID, purpose)
}

func (s *Service) ConsumeToken(ctx context.Context, raw string) (string, tokens.Purpose, error) {
	return s.tokens.Consume(ctx, raw)
}

// --- API keys (workspace-scoped machine identities) ----------------------------

// IssueServiceAccountKey mints a workspace-scoped API key acting as the service
// account. A non-positive ttl issues a key that never expires.
func (s *Service) IssueServiceAccountKey(
	ctx context.Context,
	workspaceID, serviceAccountID, name string,
	ttl time.Duration,
) (kagi.APIKey, error) {
	return s.apiKeys.Issue(
		ctx,
		kagi.TenantID(workspaceID),
		serviceAccountID,
		ActorTypeServiceAccount,
		name,
		nil,
		ttl,
	)
}

func (s *Service) RevokeServiceAccountKeys(
	ctx context.Context,
	workspaceID, serviceAccountID string,
) error {
	return s.apiKeys.RevokeAll(ctx, kagi.TenantID(workspaceID), serviceAccountID)
}

// --- Sessions ------------------------------------------------------------------

// IssueUserSession issues a kagi session for a global user and sets the
// session cookie.
func (s *Service) IssueUserSession(
	ctx context.Context,
	w http.ResponseWriter,
	u kagi.User,
	m kagi.Method,
) (kagi.Session, error) {
	return s.Kagi.IssueSession(ctx, w, "", u, m)
}

func (s *Service) ClearSession(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	s.Kagi.Sessions.ClearSession(ctx, w, r)
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
