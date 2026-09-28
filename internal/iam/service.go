// Package iam owns identity: users, credentials, sessions, and one-time
// tokens. It never answers "may this actor do X".
//
// Users are global. A workspace only gains authority over an account once it
// has verified the account's email domain, see managedBy.
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

type Action string

const (
	ActionUserCreated     Action = "UserCreated"
	ActionUserDeleted     Action = "UserDeleted"
	ActionUserDeactivated Action = "UserDeactivated"
	ActionLoginSucceeded  Action = "Login"
	ActionLoginDenied     Action = "LoginDenied"
	ActionSessionIssued   Action = "SessionIssued"
	ActionSessionRevoked  Action = "SessionRevoked"
	ActionPasswordSet     Action = "PasswordSet"
	ActionCredentialAdded Action = "CredentialAdded" //nolint:gosec // an audit action name, not a credential
)

type Event struct {
	Action      Action
	Kind        Kind
	Method      Method
	UserID      string
	Email       string
	WorkspaceID string
	Detail      string
}

// Sink implementations must be fast or async, they run inline on auth paths.
type Sink interface {
	Record(ctx context.Context, e Event)
}

// Deps requires Conn, Cache, Secret, and BaseURL.
type Deps struct {
	BaseURL string
	Conn    txRunner
	Cache   Cache
	// Secret keys the DPoP server nonce.
	Secret []byte
	Events Sink
	// Password zero value selects defaults.
	Password         PasswordParams
	PasskeyRPOrigins []string
	// StrictEmail needs DNS, so it is for the public SaaS, not air-gapped installs.
	StrictEmail bool
	// CanJoin gates joins on the seat cap. used is read in the joining tx.
	CanJoin func(ctx context.Context, workspaceID string, used int64) error
}

// egressConfig must stay off in multi-tenant deployments, since workspace
// admins pick the IdP URLs the server fetches.
type egressConfig struct {
	AllowPrivate bool `env:"NOKKU_SSO_ALLOW_PRIVATE_NETWORKS"`
}

// txRunner is satisfied by *db.Connection.
type txRunner interface {
	Sys() db.Querier
	WithTx(ctx context.Context, fn func(*db.Queries) error) error
	WithWorkspace(ctx context.Context, fn func(*db.Queries) error) error
	WithActor(ctx context.Context, actorID string, fn func(*db.Queries) error) error
}

// Service hooks are set by the host after New.
type Service struct {
	sys     db.Querier // nokku_system, bypasses RLS
	conn    txRunner
	cache   Cache
	events  Sink
	baseURL string
	secure  bool
	now     func() time.Time
	canJoin func(ctx context.Context, workspaceID string, used int64) error
	strict  bool
	idp     *http.Client // IdP egress, see newProviderClient

	// OnUserLogin fires after an interactive browser login set its cookie.
	OnUserLogin func(w http.ResponseWriter, r *http.Request, u *db.User, method Method)
	// OnNewDeviceLogin fires on a detached goroutine.
	OnNewDeviceLogin func(ctx context.Context, u *db.User, sess *db.Session, label, ip string)
	OnPasskeySignup  func(r *http.Request, u *db.User)

	Password *PasswordManager
	DPoP     *DPoPVerifier
	Device   *DeviceFlow
	OIDC     *oidcFlow
	OAuth2   *oauth2Flow
	SAML     *samlFlow
	Passkey  *passkeyFlow
	SCIM     *SCIMFlow
}

// New also seeds social providers and the bootstrap admin from the
// environment, and loads or creates the SAML SP keypair.
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
		strict:  d.StrictEmail,
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

// asSelf runs fn under RLS so it only reaches the request user's own rows.
func (s *Service) asSelf(ctx context.Context, fn func(*db.Queries) error) error {
	userID := UserIDFromContext(ctx)
	if userID == "" {
		return ErrNotFound
	}
	return s.conn.WithActor(ctx, userID, fn)
}

func (s *Service) record(ctx context.Context, e Event) {
	if s.events != nil {
		s.events.Record(ctx, e)
	}
}
