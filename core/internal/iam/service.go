// Package iam owns identity and never answers "may this actor do X". Every call runs inside the request's workspace.
package iam

import (
	"context"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/cache"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/egress"
)

type Method string

const (
	MethodPasskey   Method = "passkey"
	MethodMagicLink Method = "magic_link"
	MethodOIDC      Method = "oidc"
	MethodDevice    Method = "device"
	MethodToken     Method = "token" // a key made by hand, shown once
	MethodSCIM      Method = "scim"
)

// action is the name an event gets in the audit log.
type action string

const (
	actionUserCreated     action = "UserCreated"
	actionUserDeleted     action = "UserDeleted"
	actionUserActivated   action = "UserActivated"
	actionUserDeactivated action = "UserDeactivated"
	actionLoginSucceeded  action = "Login"
	actionLoginDenied     action = "LoginDenied"
	actionSessionIssued   action = "SessionIssued"
	actionSessionRevoked  action = "SessionRevoked"
	actionEmailChanged    action = "EmailChanged"
	actionCredentialAdded action = "CredentialAdded" //nolint:gosec // an audit action name, not a credential
)

type event struct {
	Action action
	Kind   actor.Kind
	Method Method
	UserID string
	Email  string
	Detail string
}

// Deps requires Conn and Secret.
type Deps struct {
	Conn *db.Connection
	// Secret keys the DPoP server nonce and the flow cookies.
	Secret []byte
	// Audit gets the sign-in events. Unset, they are not recorded.
	Audit *audit.Service
	// Secure marks cookies, true when the server is reached over https.
	Secure bool
	// StrictEmail needs DNS, so it is for the public SaaS, not air-gapped installs.
	StrictEmail bool
	// CanJoin gates new users on the seat cap. used is read in the creating tx.
	CanJoin func(ctx context.Context, workspaceID string, used int64) error

	// SendMagicLink mails a sign-in link. Unset, the login page offers none.
	SendMagicLink func(ctx context.Context, userID, email, link string, expiry time.Duration) error
	// SendSignupLink mails the link that creates an invited account.
	SendSignupLink func(ctx context.Context, email, name, workspace, link string, expiry time.Duration) error
	// SendNewLogin tells an account about a sign-in from a device new to it.
	SendNewLogin func(ctx context.Context, userID, email, deviceID, deviceName, ip string) error
}

type Service struct {
	conn    *db.Connection
	audit   *audit.Service
	secure  bool
	now     func() time.Time
	canJoin func(ctx context.Context, workspaceID string, used int64) error
	strict  bool
	idp     *http.Client // guarded, see egress.NewClient
	// flowAEAD seals flow state into its cookie. XChaCha, anyone can start a flow and random nonces must never run out.
	flowAEAD cipher.AEAD
	// spent holds the ids of flows that ended in a login, see spendFlow.
	spent *cache.TTL[string, struct{}]

	sendMagicLink  func(ctx context.Context, userID, email, link string, expiry time.Duration) error
	sendSignupLink func(ctx context.Context, email, name, workspace, link string, expiry time.Duration) error
	sendNewLogin   func(ctx context.Context, userID, email, deviceID, deviceName, ip string) error

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
		conn:           d.Conn,
		audit:          d.Audit,
		secure:         d.Secure,
		now:            time.Now,
		canJoin:        d.CanJoin,
		strict:         d.StrictEmail,
		sendMagicLink:  d.SendMagicLink,
		sendSignupLink: d.SendSignupLink,
		sendNewLogin:   d.SendNewLogin,
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
	s.spent = cache.New[string, struct{}](spentFlowEntries, flowStateTTL)
	s.DPoP = &DPoPVerifier{
		secret: d.Secret,
		// The iat check takes a proof for 2*dpopMaxSkew at most. The third is slack for a wall clock that steps back.
		replay: cache.New[[32]byte, struct{}](dpopReplayEntries, 3*dpopMaxSkew),
		now:    s.now,
	}
	s.Device = &DeviceFlow{svc: s}
	s.OIDC = newOIDCFlow(s)
	s.Passkey = newPasskeyFlow(s)
	s.SCIM = newSCIMFlow(s)

	go s.cleanup(ctx)
	return s, nil
}

func (s *Service) MagicLinkEnabled() bool {
	return s.sendMagicLink != nil
}

// baseURL is where this workspace lives, the root of every link and cookie.
func baseURL(ctx context.Context) string {
	ws, _ := actor.WorkspaceFromContext(ctx)
	return ws.BaseURL
}

func (s *Service) record(ctx context.Context, e event) {
	if s.audit == nil {
		return
	}
	details := map[string]any{}
	if e.Method != "" {
		details["method"] = string(e.Method)
	}
	if e.Detail != "" {
		details["detail"] = e.Detail
	}
	s.audit.Record(ctx, &audit.Event{
		Action:    string(e.Action),
		ActorID:   e.UserID,
		ActorKind: string(e.Kind),
		ActorName: e.Email,
		OK:        e.Action != actionLoginDenied,
		Details:   details,
	})
}

// notifyNewDevice is detached, the sign-in does not wait for the mail.
func (s *Service) notifyNewDevice(ctx context.Context, u *db.User, deviceID, name, ip string) {
	if s.sendNewLogin == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mailTimeout)
	go func() {
		defer cancel()
		if err := s.sendNewLogin(ctx, u.ID, u.Email, deviceID, name, ip); err != nil {
			slog.Warn("new login email not sent", "error", err)
		}
	}()
}
