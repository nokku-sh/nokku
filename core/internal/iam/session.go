package iam

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"uuid"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/dpop"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/crypto"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/realip"
)

const (
	// One per account, or every account switch would count as a new device.
	deviceCookiePrefix = "nokku_device_"
	deviceTTL          = 180 * 24 * time.Hour
)

// recentSignIn is the max age of a session for a call marked fresh.
const recentSignIn = 10 * time.Minute

// SSOSessionTTL is how long a person stays signed in where single sign-on is
// required. Nothing asks the provider again in between, so this is how long
// someone removed there keeps a session.
const SSOSessionTTL = 24 * time.Hour

var tokenKinds = map[actor.Kind]crypto.TokenKind{
	actor.KindUser:           crypto.TokenSession,
	actor.KindCLI:            crypto.TokenCLI,
	actor.KindDaemon:         crypto.TokenDaemon,
	actor.KindServiceAccount: crypto.TokenServiceAccount,
	actor.KindSCIM:           crypto.TokenSCIM,
}

// errSignInAgain is a session too old, RequireRecentSignIn ended it already.
var errSignInAgain = errors.New("sign in again to continue")

type TokenParams struct {
	// SubjectID is the user, service account or daemon, empty for SCIM.
	SubjectID string
	Kind      actor.Kind
	Method    Method
	// Binding is the DPoP jkt, empty for cookie sessions and keys.
	Binding string
	// SSHKey is the normalized key nk signed in with, required for KindCLI.
	SSHKey string
	Label  string
	// TTL zero never expires, the token must be revoked explicitly.
	TTL time.Duration
	// NotAfter cuts the TTL short when set.
	NotAfter time.Time
	// WorkloadJTI is the job token this one came from, see workload_jti.
	WorkloadJTI string
}

// IssueToken is for machines, a person's token goes through IssueSignIn.
func (s *Service) IssueToken(ctx context.Context, p TokenParams) (*db.AccessToken, string, error) {
	if p.Kind == actor.KindUser || p.Kind == actor.KindCLI {
		return nil, "", errors.New("iam: a person's token comes from IssueSignIn")
	}
	return s.issue(ctx, s.conn.Tenant(), p)
}

// IssueSignIn is the one way a person gets a token, in a browser or in nk.
func (s *Service) IssueSignIn(ctx context.Context, u *db.User, p TokenParams) (*db.AccessToken, string, error) {
	return s.issueSignIn(ctx, s.conn.Tenant(), u, p)
}

// q ties the token to the caller's transaction, if it has one.
func (s *Service) issueSignIn(
	ctx context.Context,
	q *db.Queries,
	u *db.User,
	p TokenParams,
) (*db.AccessToken, string, error) {
	deny := func(err error, detail string) (*db.AccessToken, string, error) {
		s.record(ctx, event{Action: actionLoginDenied, Method: p.Method, UserID: u.ID, Email: u.Email, Detail: detail})
		return nil, "", err
	}
	if !u.Active {
		return deny(ErrInactive, "inactive")
	}
	w, err := q.GetWorkspace(ctx)
	if err != nil {
		return nil, "", err
	}
	if w.Settings.GetEnforceSso() {
		// The owner keeps passkey and link, to fix a broken provider.
		breakGlass := u.Role == nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER &&
			(p.Method == MethodPasskey || p.Method == MethodMagicLink)
		if p.Method != MethodOIDC && !breakGlass {
			return deny(ErrSSORequired, "sso enforced")
		}
		// Zero would never expire.
		if p.TTL == 0 || p.TTL > SSOSessionTTL {
			p.TTL = SSOSessionTTL
		}
	}
	// An unclaimed workspace is purged, so failing to claim fails the sign-in.
	if err := q.ClaimWorkspace(ctx); err != nil {
		return nil, "", err
	}
	p.SubjectID = u.ID
	return s.issue(ctx, q, p)
}

// issue pins the token to the request's workspace and stores only its hash.
func (s *Service) issue(ctx context.Context, q *db.Queries, p TokenParams) (*db.AccessToken, string, error) {
	kind, ok := tokenKinds[p.Kind]
	if !ok {
		return nil, "", errors.New("iam: no token for kind " + string(p.Kind))
	}
	token, tokenHash := crypto.NewToken(kind)
	now := s.now()
	params := &db.CreateAccessTokenParams{
		TokenHash: tokenHash,
		Kind:      string(p.Kind),
		Method:    string(p.Method),
		Binding:   p.Binding,
		SshKey:    p.SSHKey,
		Label:     p.Label,
	}
	// A login is a use, a key made by hand is not used until a call carries it.
	if p.Kind != actor.KindServiceAccount && p.Kind != actor.KindSCIM {
		params.LastSeenAt = &now
	}
	if p.SubjectID != "" {
		params.SubjectID = &p.SubjectID
	}
	if meta, ok := actor.RequestMetaFromContext(ctx); ok {
		params.UserAgent = meta.UserAgent()
		params.Ip = meta.ClientIP()
	}
	if p.TTL > 0 {
		params.ExpiresAt = new(now.Add(p.TTL))
		if !p.NotAfter.IsZero() && p.NotAfter.Before(*params.ExpiresAt) {
			params.ExpiresAt = &p.NotAfter
		}
	}
	params.WorkloadJti = nonEmpty(p.WorkloadJTI)
	tok, err := q.CreateAccessToken(ctx, params)
	if err != nil {
		return nil, "", err
	}
	// A key is made by an RPC the audit log already records.
	if p.Kind != actor.KindServiceAccount && p.Kind != actor.KindSCIM {
		s.record(ctx, event{Action: actionSessionIssued, Kind: p.Kind, Method: p.Method, UserID: p.SubjectID})
	}
	return tok, token, nil
}

func (s *Service) completeLogin(ctx context.Context, u *db.User, method Method) (*http.Cookie, error) {
	sess, token, err := s.IssueSignIn(ctx, u, TokenParams{Kind: actor.KindUser, Method: method, TTL: sessionTTL})
	if err != nil {
		return nil, err
	}
	s.record(
		ctx,
		event{Action: actionLoginSucceeded, Kind: actor.KindUser, Method: method, UserID: u.ID, Email: u.Email},
	)
	return s.newCookie(sessionCookieName, token, *sess.ExpiresAt), nil
}

// IssueDaemonSession replaces earlier sessions and does not expire. A deleted
// daemon's next sync removes it, or the expiry the delete set does.
func (s *Service) IssueDaemonSession(ctx context.Context, daemonID, binding string) (string, error) {
	if _, err := s.revokeSubject(ctx, daemonID); err != nil {
		return "", err
	}
	_, token, err := s.IssueToken(ctx, TokenParams{
		SubjectID: daemonID,
		Kind:      actor.KindDaemon,
		Method:    MethodDevice,
		Binding:   binding,
	})
	return token, err
}

// RememberDevice returns nil for a known browser. A new one gets a mail too.
func (s *Service) RememberDevice(ctx context.Context, header http.Header, remoteAddr string, u *db.User) *http.Cookie {
	name := deviceCookiePrefix + u.ID
	if raw := s.cookieValue(header, name); raw != "" && s.seenDevice(ctx, u.ID, deviceKey(raw)) {
		return nil
	}
	token := crypto.RandomString(32)
	meta := actor.RequestMeta{Header: header, RemoteAddr: remoteAddr}
	d, err := s.addDevice(
		ctx,
		u,
		deviceKey(token),
		meta.UserAgent(),
		deviceNameFromUA(header.Get("User-Agent")),
		realip.Client(header, remoteAddr),
	)
	if err != nil {
		slog.Error("failed to remember device", "error", err)
		return nil
	}
	return s.newCookie(name, token, d.ExpiresAt)
}

func deviceKey(cookie string) string {
	return crypto.HashToken(cookie).Hash()
}

// seenDevice takes a failed lookup as new, a mail too many beats a missed one.
func (s *Service) seenDevice(ctx context.Context, userID, key string) bool {
	_, err := s.conn.Tenant().SeenKnownDevice(ctx, &db.SeenKnownDeviceParams{UserID: userID, Key: key, Now: s.now()})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		slog.Error("failed to look up known devices", "error", err)
	}
	return err == nil
}

// addDevice takes userAgent cleaned. ip is cleaned for the row, not the mail.
func (s *Service) addDevice(ctx context.Context, u *db.User, key, userAgent, name, ip string) (*db.KnownDevice, error) {
	now := s.now()
	d, err := s.conn.Tenant().AddKnownDevice(ctx, &db.AddKnownDeviceParams{
		UserID:    u.ID,
		Key:       key,
		Ip:        strings.ToValidUTF8(ip, ""),
		UserAgent: userAgent,
		ExpiresAt: now.Add(deviceTTL),
		Now:       now,
	})
	if err != nil {
		return nil, err
	}
	s.notifyNewDevice(ctx, u, d.ID, name, ip)
	return d, nil
}

func (s *Service) ListDevices(ctx context.Context) ([]*db.KnownDevice, error) {
	return s.conn.Tenant().ListKnownDevices(ctx, actor.UserIDFromContext(ctx))
}

// ForgetDevice only reaches the caller's own devices.
func (s *Service) ForgetDevice(ctx context.Context, id string) error {
	if _, err := uuid.Parse(id); err != nil {
		return nil
	}
	return s.conn.Tenant().
		DeleteKnownDevice(ctx, &db.DeleteKnownDeviceParams{UserID: actor.UserIDFromContext(ctx), ID: id})
}

// verifyToken stays in the request's workspace. Bad tokens fail before lookup.
func (s *Service) verifyToken(ctx context.Context, token string, kinds ...crypto.TokenKind) (db.AccessToken, error) {
	if token == "" {
		return db.AccessToken{}, errNoSession
	}
	hash, ok := crypto.TokenHash(token, kinds...)
	if !ok {
		return db.AccessToken{}, errInvalidCredentials
	}
	tok, err := s.conn.Tenant().GetAccessToken(ctx, hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return db.AccessToken{}, errNoSession
	}
	if err != nil {
		return db.AccessToken{}, err
	}
	if tok.ExpiresAt != nil && !tok.ExpiresAt.After(s.now()) {
		_ = s.conn.Tenant().DeleteAccessToken(ctx, tok.ID)
		return db.AccessToken{}, errSessionExpired
	}
	return *tok, nil
}

func (s *Service) noteSeen(ctx context.Context, tok db.AccessToken) {
	now := s.now()
	if tok.LastSeenAt != nil && now.Sub(*tok.LastSeenAt) < sessionSeenEvery {
		return
	}
	err := s.conn.Tenant().TouchAccessToken(ctx, &db.TouchAccessTokenParams{ID: tok.ID, LastSeenAt: &now})
	if err != nil {
		slog.Warn("failed to note token activity", "error", err)
	}
}

func (s *Service) ListSessions(ctx context.Context) ([]*db.AccessToken, error) {
	userID := actor.UserIDFromContext(ctx)
	if userID == "" {
		return nil, nil
	}
	return s.conn.Tenant().ListUserSessions(ctx, userID)
}

// Logout needs DPoP for header tokens, a leaked token alone ends no session.
func (s *Service) Logout(ctx context.Context, header http.Header, procedure string) error {
	p, tok, err := s.Authenticate(ctx, header, procedure)
	if errors.Is(err, dpop.ErrNonce) || errors.Is(err, ErrDPoPRequired) {
		return err
	}
	if err != nil {
		return nil
	}
	if tok.WorkloadJti != nil {
		// Its row stays, it says the job token is spent.
		_, err := s.conn.Tenant().
			RevokeWorkloadToken(ctx, &db.RevokeWorkloadTokenParams{ID: tok.ID, ServiceAccountID: p.ID})
		return err
	}
	if p.Kind != actor.KindUser && p.Kind != actor.KindCLI {
		return nil
	}
	if err := s.conn.Tenant().DeleteAccessToken(ctx, tok.ID); err != nil {
		return err
	}
	s.record(ctx, event{Action: actionSessionRevoked, Kind: p.Kind, Method: Method(tok.Method), UserID: p.ID})
	return nil
}

func (s *Service) revokeSubject(ctx context.Context, subjectID string) (int64, error) {
	return s.conn.Tenant().DeleteSubjectTokens(ctx, subjectID)
}

// DeleteOwnSession only reaches the caller's own sessions.
func (s *Service) DeleteOwnSession(ctx context.Context, id string) error {
	userID := actor.UserIDFromContext(ctx)
	if userID == "" {
		return nil
	}
	return s.conn.TenantTx(ctx, func(q *db.Queries) error {
		rows, err := q.ListUserSessions(ctx, userID)
		if err != nil {
			return err
		}
		for _, tok := range rows {
			if tok.ID == id {
				return q.DeleteAccessToken(ctx, tok.ID)
			}
		}
		return nil
	})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

func (s *Service) touchCredential(ctx context.Context, id string) {
	err := s.conn.Tenant().TouchCredential(ctx, id)
	if err != nil {
		slog.Warn("failed to mark credential used", "error", err)
	}
}

// FreshFor is how long a session stays fresh. nk never is.
func (s *Service) FreshFor(tok *db.AccessToken) time.Duration {
	if tok.Kind != string(actor.KindUser) {
		return 0
	}
	return max(0, recentSignIn-s.now().Sub(tok.CreatedAt))
}

// RequireRecentSignIn stops a stolen cookie becoming a lasting passkey or
// address. An old session ends here, or the sign-in page would send it back.
func (s *Service) RequireRecentSignIn(ctx context.Context) error {
	tok, ok := CurrentToken(ctx)
	if !ok || tok.Kind != string(actor.KindUser) {
		return errSignInAgain
	}
	if s.FreshFor(&tok) > 0 {
		return nil
	}
	if err := s.conn.Tenant().DeleteAccessToken(ctx, tok.ID); err != nil {
		return err
	}
	return errSignInAgain
}
