// Package iam owns identity: users, credentials, sessions, and one-time
// tokens. It never answers "may this actor do X".
//
// Every call runs inside the workspace the request's host named. A session,
// credential or token of another workspace is simply not found.
package iam

import (
	"context"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"net/http"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/cache"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/egress"
)

type Method string

const (
	MethodPasskey   Method = "passkey"
	MethodMagicLink Method = "magic_link"
	MethodOIDC      Method = "oidc"
	MethodDevice    Method = "device"
	MethodSCIM      Method = "scim"
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
	ActionEmailChanged    Action = "EmailChanged"
	ActionCredentialAdded Action = "CredentialAdded" //nolint:gosec // an audit action name, not a credential
)

type Event struct {
	Action Action
	Kind   actor.Kind
	Method Method
	UserID string
	Email  string
	Detail string
}

// Sink implementations must be fast or async, they run inline on auth paths.
type Sink interface {
	Record(ctx context.Context, e Event)
}

// Deps requires Conn and Secret.
type Deps struct {
	Conn *db.Connection
	// Secret keys the DPoP server nonce and the flow cookies.
	Secret []byte
	Events Sink
	// Secure marks cookies, true when the server is reached over https.
	Secure bool
	// StrictEmail needs DNS, so it is for the public SaaS, not air-gapped installs.
	StrictEmail bool
	// Debug adds the Vite dev server to the passkey origins.
	Debug bool
	// CanJoin gates new users on the seat cap. used is read in the creating tx.
	CanJoin func(ctx context.Context, workspaceID string, used int64) error
}

// Service hooks are set by the host after New.
type Service struct {
	conn    *db.Connection
	events  Sink
	secure  bool
	now     func() time.Time
	canJoin func(ctx context.Context, workspaceID string, used int64) error
	strict  bool
	debug   bool
	idp     *http.Client // guarded, see egress.NewClient
	// flowAEAD seals the state of browser flows into their cookie. XChaCha,
	// since anyone can start a flow and random nonces must never run out.
	flowAEAD cipher.AEAD
	// spent holds the ids of flows that ended in a login, see spendFlow.
	spent *cache.Memory

	// OnUserLogin fires after an interactive browser login set its cookie.
	OnUserLogin func(w http.ResponseWriter, r *http.Request, u *db.User, method Method)
	// OnNewDeviceLogin fires on a detached goroutine.
	OnNewDeviceLogin func(ctx context.Context, u *db.User, sess *db.Session, label, ip string)
	// SendMagicLink mails a sign-in link. Unset, the login page offers none.
	SendMagicLink func(ctx context.Context, u *db.User, link string, ttl time.Duration) error
	// SendSignupLink mails the link that creates an invited account.
	SendSignupLink func(ctx context.Context, email, name, link string, ttl time.Duration) error

	DPoP    *DPoPVerifier
	Device  *DeviceFlow
	OIDC    *oidcFlow
	Passkey *passkeyFlow
	SCIM    *SCIMFlow
}

func New(ctx context.Context, d Deps) (*Service, error) {
	if d.Conn == nil || len(d.Secret) == 0 {
		return nil, errors.New("iam: conn and secret are required")
	}
	s := &Service{
		conn:    d.Conn,
		events:  d.Events,
		secure:  d.Secure,
		now:     time.Now,
		canJoin: d.CanJoin,
		strict:  d.StrictEmail,
		debug:   d.Debug,
	}
	var err error
	if s.idp, err = egress.NewClient(providerHTTPTimeout); err != nil {
		return nil, err
	}
	flowKey, err := hkdf.Key(sha256.New, d.Secret, nil, "nokku flow cookie v1", chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	if s.flowAEAD, err = chacha20poly1305.NewX(flowKey); err != nil {
		return nil, err
	}
	s.spent = cache.NewMemory(spentFlowEntries)
	s.DPoP = &DPoPVerifier{
		secret:     d.Secret,
		replay:     cache.NewMemory(dpopReplayEntries),
		anonReplay: cache.NewMemory(dpopAnonReplayEntries),
		now:        s.now,
	}
	s.Device = &DeviceFlow{svc: s, grants: cache.NewMemory(deviceGrantEntries)}
	s.OIDC = newOIDCFlow(s)
	s.Passkey = newPasskeyFlow(s)
	s.SCIM = newSCIMFlow(s)

	go s.cleanup(ctx)
	return s, nil
}

// MagicLinkEnabled is whether the login page may offer a sign-in link.
func (s *Service) MagicLinkEnabled() bool {
	return s.SendMagicLink != nil
}

// inWorkspace runs fn pinned to the request's workspace, under RLS.
func (s *Service) inWorkspace(ctx context.Context, fn func(q *db.Queries, ws string) error) error {
	return s.conn.WithWorkspace(ctx, func(q *db.Queries) error {
		return fn(q, actor.WorkspaceIDFromContext(ctx))
	})
}

// baseURL is where this workspace lives, the root of every link and cookie.
func baseURL(ctx context.Context) string {
	ws, _ := actor.WorkspaceFromContext(ctx)
	return ws.BaseURL
}

func (s *Service) record(ctx context.Context, e Event) {
	if s.events != nil {
		s.events.Record(ctx, e)
	}
}
