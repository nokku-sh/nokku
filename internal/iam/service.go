// Package iam owns nokku's identity and access management: users,
// credentials, sessions, and one-time tokens. It is the merged-back auth
// engine (see docs/adr/0001-merge-auth-back-into-nokku.md): identity lives in
// the same schema as the domain so memberships, teams, and audit join it in
// plain SQL.
//
// The package deals in identities only. Roles, permissions, workspaces, and
// billing stay outside; iam never answers "may this actor do X".
package iam

import (
	"context"
	"errors"
	"net/http"
	"time"

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

// Event is an auth lifecycle event. The audit service subscribes as a Sink;
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

// User is the identity user record. It aliases the generated pointer type
// so callers depend on the iam vocabulary, not the storage layer.
type User = *db.User

// Deps configures the service. Querier is required; everything else has a
// sane default.
type Deps struct {
	Querier db.Querier
	// BaseURL drives the session cookie's Secure attribute and email
	// link construction.
	BaseURL string
	// Events receives lifecycle events. Optional; nil disables recording.
	Events Sink
	// Session configures issuance. A zero TTL selects the default.
	Session SessionOptions
	// Password selects argon2id parameters. A zero value selects defaults.
	Password PasswordParams
	// Secret keys the DPoP server nonce. Required for DPoP; derives from
	// NOKKU_SECRET.
	Secret []byte
	// Conn runs workspace-scoped queries under RLS (domains, SSO
	// providers). Required for the managers that touch tenant tables.
	Conn txRunner
	// Cache backs SSO flow state and the device flow. Required for both.
	Cache Cache
	// Device flow settings; the flow builds only when Cache is set.
	// DeviceVerificationURI string
	DeviceSessionTTL time.Duration
	// OnSSOLogin fires after a successful SSO login under a
	// workspace-scoped provider (membership auto-join).
	OnSSOLogin func(ctx context.Context, userID, workspaceID string) error
	// OnUserLogin fires after a successful interactive user login (SSO or
	// passkey), after the session cookie is set. Hosts attach post-login
	// side effects: device remembering, new-login alerts.
	OnUserLogin func(w http.ResponseWriter, r *http.Request, u User, method Method)
	// OnPasskeySignup fires after passkey-only signup created the account,
	// so the host can send its verification email.
	OnPasskeySignup func(r *http.Request, u User)
	// Passkey relying-party settings; the flow builds only when Cache and
	// PasskeyRPID are set.
	PasskeyRPOrigins []string
}

// txRunner runs store reads and writes in the role the table needs: the
// system role for global tables, the RLS-pinned role for tenant tables.
// Narrow on purpose: *db.Connection satisfies it, tests provide in-memory
// implementations.
type txRunner interface {
	WithTx(ctx context.Context, fn func(*db.Queries) error) error
	WithWorkspace(ctx context.Context, fn func(*db.Queries) error) error
}

// Service is the iam engine. Managers hang off it and share its querier and
// event sink.
type Service struct {
	q               db.Querier
	baseURL         string
	conn            txRunner
	cache           Cache
	events          Sink
	OnSSOLogin      func(ctx context.Context, userID, workspaceID string) error
	OnUserLogin     func(w http.ResponseWriter, r *http.Request, u User, method Method)
	OnPasskeySignup func(r *http.Request, u User)
	Password        *PasswordManager
	Sessions        *SessionManager
	DPoP            *DPoPVerifier
	Device          *DeviceFlow
	OIDC            *oidcFlow
	OAuth2          *oauth2Flow
	SAML            *samlFlow
	Passkey         *passkeyFlow
	SCIM            *SCIMFlow

	now func() time.Time
}

// New builds the service.
func New(d Deps) (*Service, error) {
	if d.Querier == nil {
		return nil, errors.New("iam: querier is required")
	}
	if d.Session.TTL == 0 {
		d.Session.TTL = 24 * time.Hour
	}
	svc := &Service{
		q:               d.Querier,
		baseURL:         d.BaseURL,
		conn:            d.Conn,
		cache:           d.Cache,
		events:          d.Events,
		OnSSOLogin:      d.OnSSOLogin,
		OnUserLogin:     d.OnUserLogin,
		OnPasskeySignup: d.OnPasskeySignup,
		now:             time.Now,
	}
	svc.Password = newPasswordManager(svc, d.Password)
	svc.Sessions = &SessionManager{svc: svc, opts: d.Session}
	if len(d.Secret) > 0 {
		// Replay detection rides the shared cache the service already
		// carries; a nil cache disables it (tests only).
		var replay ReplayStore
		if d.Cache != nil {
			replay = cacheReplay{d.Cache}
		}
		dpop, err := NewDPoPVerifier(DPoPOptions{
			NonceSecret: d.Secret,
			Replay:      replay,
			Now:         svc.now,
		})
		if err != nil {
			return nil, err
		}
		svc.DPoP = dpop
	}
	if svc.cache != nil && svc.DPoP != nil {
		flow, err := NewDeviceFlow(svc, DeviceOptions{
			Cache:      svc.cache,
			SessionTTL: d.DeviceSessionTTL,
		})
		if err != nil {
			return nil, err
		}
		svc.Device = flow
	}
	if svc.cache != nil {
		svc.OIDC = newOIDCFlow(svc)
		svc.OAuth2 = newOAuth2Flow(svc)
		// Unlike the flows above, the SAML flow's error must not be
		// swallowed: a nil receiver would panic on the first /saml/*
		// request, so construction failure fails startup like the rest.
		saml, err := newSAMLFlow(svc, SAMLConfig{
			AcsURL:     d.BaseURL + "/saml/acs",
			SPEntityID: d.BaseURL + "/saml/metadata",
		})
		if err != nil {
			return nil, err
		}
		svc.SAML = saml
	}
	if svc.cache != nil {
		passkey, err := newPasskeyFlow(
			svc,
			d.PasskeyRPOrigins,
		)
		if err != nil {
			return nil, err
		}
		svc.Passkey = passkey
	}
	if svc.conn != nil {
		svc.SCIM = newSCIMFlow(svc)
	}
	return svc, nil
}

// record emits an event when a sink is configured.
func (s *Service) record(ctx context.Context, e Event) {
	if s.events == nil {
		return
	}
	s.events.Record(ctx, e)
}
