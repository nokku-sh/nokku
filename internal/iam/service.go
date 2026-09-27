// Package iam owns nokku's identity and access management: users,
// credentials, sessions, and one-time tokens. Identity lives in the same
// schema as the domain so memberships, teams, and audit join it in plain SQL.
//
// The package deals in identities only. Roles, permissions, workspaces, and
// billing stay outside, iam never answers "may this actor do X".
//
// Users are global. A workspace gains authority over an account (SCIM
// changes, SSO email matching, JIT provisioning) only when it has verified
// the account's email domain. See managedBy.
package iam

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"

	"github.com/nokku-sh/nokku/internal/db"
)

// Method is how a credential or session was established.
type Method string

const (
	MethodPassword   Method = "password"
	MethodPasskey    Method = "passkey"
	MethodOIDC       Method = "oidc"
	MethodOAuth2     Method = "oauth2"
	MethodSAML       Method = "saml"
	MethodBackupCode Method = "backup_code"
	MethodDevice     Method = "device"
	MethodSCIM       Method = "scim"
)

// Action identifies an auth lifecycle event for the audit sink.
type Action string

const (
	ActionUserCreated     Action = "user_created"
	ActionUserDeleted     Action = "user_deleted"
	ActionUserDeactivated Action = "user_deactivated"
	ActionLoginSucceeded  Action = "login_succeeded"
	ActionLoginDenied     Action = "login_denied"
	ActionSessionIssued   Action = "session_issued"
	ActionSessionRevoked  Action = "session_revoked"
	ActionPasswordSet     Action = "password_set"
	ActionCredentialAdded Action = "credential_added" //nolint:gosec // an audit action name, not a credential
)

// Event is an auth lifecycle event. The audit service subscribes as a Sink,
// iam never writes audit rows itself.
type Event struct {
	Action      Action
	Kind        Kind
	Method      Method
	UserID      string
	Email       string
	WorkspaceID string
	Detail      string
}

// Sink receives auth events. Implementations must be fast or async: they run
// inline on auth paths.
type Sink interface {
	Record(ctx context.Context, e Event)
}

// Deps configures the service. Conn, Cache, Secret, and BaseURL are required.
type Deps struct {
	// BaseURL drives the cookie Secure attribute, the passkey RP ID, and the
	// DPoP htu.
	BaseURL string
	Conn    txRunner
	// Cache backs SSO flow state, passkey ceremonies, the device flow, and
	// DPoP replay tracking.
	Cache Cache
	// Secret keys the DPoP server nonce. It derives from NOKKU_SECRET.
	Secret []byte
	// Events receives lifecycle events. Optional.
	Events Sink
	// Password selects argon2id parameters. A zero value selects defaults.
	Password         PasswordParams
	PasskeyRPOrigins []string
	// CanJoin gates joins on the plan's seat cap. used is the member count
	// read in the joining transaction. Optional.
	CanJoin func(ctx context.Context, workspaceID string, used int64) error
}

// egressConfig lets self-hosted installs reach an IdP on a private network.
// Leave it off for a multi-tenant deployment: workspace admins pick the IdP
// URLs the server fetches.
type egressConfig struct {
	AllowPrivate bool `env:"NOKKU_SSO_ALLOW_PRIVATE_NETWORKS"`
}

// txRunner runs store reads and writes in the role the table needs: the
// system role for global tables, the RLS-pinned role for tenant tables.
// *db.Connection satisfies it.
type txRunner interface {
	// Sys runs single system statements: pre-authorization lookups that
	// cannot be tenant-scoped, and the global identity tables.
	Sys() db.Querier
	WithTx(ctx context.Context, fn func(*db.Queries) error) error
	WithWorkspace(ctx context.Context, fn func(*db.Queries) error) error
	WithActor(ctx context.Context, actorID string, fn func(*db.Queries) error) error
}

// Service is the iam engine. Flows hang off it and share its store, cache,
// and event sink. The hooks are set by the host after New.
type Service struct {
	sys     db.Querier // nokku_system, bypasses RLS
	conn    txRunner
	cache   Cache
	events  Sink
	baseURL string
	secure  bool
	now     func() time.Time
	canJoin func(ctx context.Context, workspaceID string, used int64) error
	idp     *http.Client // IdP egress, see newProviderClient

	// OnUserLogin fires after a successful interactive browser login, after
	// the session cookie is set: device remembering, new-login alerts.
	OnUserLogin func(w http.ResponseWriter, r *http.Request, u *db.User, method Method)
	// OnNewDeviceLogin fires on a detached goroutine when RememberDevice
	// issued a first session for a device.
	OnNewDeviceLogin func(ctx context.Context, u *db.User, sess *db.Session, label, ip string)
	// OnPasskeySignup fires after passkey-only signup created the account,
	// so the host can send its verification email.
	OnPasskeySignup func(r *http.Request, u *db.User)

	Password *PasswordManager
	DPoP     *DPoPVerifier
	Device   *DeviceFlow
	OIDC     *oidcFlow
	OAuth2   *oauth2Flow
	SAML     *samlFlow
	Passkey  *passkeyFlow
	SCIM     *SCIMFlow
}

// New builds the service, seeds the social providers and the bootstrap admin
// from the environment, and loads or creates the SAML SP keypair.
func New(ctx context.Context, d Deps) (*Service, error) {
	if d.Conn == nil || d.Cache == nil || len(d.Secret) == 0 || d.BaseURL == "" {
		return nil, errors.New("iam: conn, cache, secret, and base url are required")
	}
	s := &Service{
		sys:     d.Conn.Sys(),
		conn:    d.Conn,
		cache:   d.Cache,
		events:  d.Events,
		baseURL: d.BaseURL,
		secure:  strings.HasPrefix(strings.ToLower(d.BaseURL), "https://"),
		now:     time.Now,
		canJoin: d.CanJoin,
	}
	cfg, err := env.ParseAs[egressConfig]()
	if err != nil {
		return nil, err
	}
	s.idp = newProviderClient(cfg.AllowPrivate)
	s.Password = newPasswordManager(s, d.Password)
	s.DPoP = &DPoPVerifier{secret: d.Secret, replay: d.Cache, now: s.now}
	s.Device = &DeviceFlow{svc: s}
	s.OIDC = newOIDCFlow(s)
	s.OAuth2 = newOAuth2Flow(s)
	if s.SAML, err = newSAMLFlow(ctx, s); err != nil {
		return nil, err
	}
	if s.Passkey, err = newPasskeyFlow(s, d.PasskeyRPOrigins); err != nil {
		return nil, err
	}
	s.SCIM = newSCIMFlow(s)

	if err := s.seedSocialProviders(ctx); err != nil {
		return nil, err
	}
	if err := s.bootstrapUser(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// asSelf runs fn as the request's user under RLS. Whatever ids the caller
// passes, fn can only reach that user's own rows.
func (s *Service) asSelf(ctx context.Context, fn func(*db.Queries) error) error {
	userID := UserIDFromContext(ctx)
	if userID == "" {
		return ErrNotFound
	}
	return s.conn.WithActor(ctx, userID, fn)
}

// record emits an event when a sink is configured.
func (s *Service) record(ctx context.Context, e Event) {
	if s.events != nil {
		s.events.Record(ctx, e)
	}
}
