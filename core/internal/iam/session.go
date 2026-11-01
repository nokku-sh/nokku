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
	// The device cookie is per account. With one name every account switch would count as a new device.
	deviceCookiePrefix = "nokku_device_"
	deviceTTL          = 180 * 24 * time.Hour
)

type TokenParams struct {
	// SubjectID is the user, service account or daemon, empty for SCIM.
	SubjectID string
	Kind      actor.Kind
	Method    Method
	// Binding is the DPoP jkt, empty for cookie sessions and keys.
	Binding string
	Label   string
	// TTL zero never expires, the token must be revoked explicitly.
	TTL time.Duration
	// NotAfter cuts the TTL short when set.
	NotAfter time.Time
	// WorkloadJTI is the job token this one came from, see workload_jti.
	WorkloadJTI string
}

// tokenKinds is the token kind of each kind of access token.
var tokenKinds = map[actor.Kind]crypto.TokenKind{
	actor.KindUser:           crypto.TokenSession,
	actor.KindCLI:            crypto.TokenCLI,
	actor.KindDaemon:         crypto.TokenDaemon,
	actor.KindServiceAccount: crypto.TokenServiceAccount,
	actor.KindSCIM:           crypto.TokenSCIM,
}

// IssueToken makes the token of a machine. A person's comes from IssueSignIn, which applies the sign-in rules first.
func (s *Service) IssueToken(ctx context.Context, p TokenParams) (*db.AccessToken, string, error) {
	if p.Kind == actor.KindUser || p.Kind == actor.KindCLI {
		return nil, "", errors.New("iam: a person's token comes from IssueSignIn")
	}
	return s.issue(ctx, p)
}

// IssueSignIn is the one way a person gets a token, in a browser or in nk. p.Method is how they proved who they are.
func (s *Service) IssueSignIn(ctx context.Context, u *db.User, p TokenParams) (*db.AccessToken, string, error) {
	deny := func(err error, detail string) (*db.AccessToken, string, error) {
		s.record(ctx, event{Action: actionLoginDenied, Method: p.Method, UserID: u.ID, Email: u.Email, Detail: detail})
		return nil, "", err
	}
	if !u.Active {
		return deny(ErrInactive, "inactive")
	}
	if p.Method != MethodOIDC {
		enforced, err := s.ssoEnforced(ctx)
		if err != nil {
			return nil, "", err
		}
		// The owner keeps the passkey and the sign-in link as the way in to fix a broken provider.
		breakGlass := u.Role == nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER &&
			(p.Method == MethodPasskey || p.Method == MethodMagicLink)
		if enforced && !breakGlass {
			return deny(ErrSSORequired, "sso enforced")
		}
	}
	// A workspace with no sign-in on record gets purged, so a sign-in that can't be recorded fails.
	if err := s.conn.Tenant().ClaimWorkspace(ctx); err != nil {
		return nil, "", err
	}
	p.SubjectID = u.ID
	return s.issue(ctx, p)
}

// issue pins the token to the request's workspace. The plaintext is returned once, only its hash is stored.
func (s *Service) issue(ctx context.Context, p TokenParams) (*db.AccessToken, string, error) {
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
	tok, err := s.conn.Tenant().CreateAccessToken(ctx, params)
	if err != nil {
		return nil, "", err
	}
	// A key is made by an RPC the audit log already records.
	if p.Kind != actor.KindServiceAccount && p.Kind != actor.KindSCIM {
		s.record(ctx, event{Action: actionSessionIssued, Kind: p.Kind, Method: p.Method, UserID: p.SubjectID})
	}
	return tok, token, nil
}

// completeLogin ends every browser sign-in.
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

func (s *Service) ssoEnforced(ctx context.Context) (bool, error) {
	w, err := s.conn.Tenant().GetWorkspace(ctx)
	if err != nil {
		return false, err
	}
	return w.Settings.GetEnforceSso(), nil
}

// IssueDaemonSession replaces earlier sessions. It does not expire while the daemon exists. Once that is deleted
// its next sync removes the session, or the expiry the delete gave it does.
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

// RememberDevice returns nil for a browser the account has used before. A new one gets a cookie and a mail.
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

// deviceKey is what a browser is recognized by, the hash of its cookie.
func deviceKey(cookie string) string {
	return crypto.HashToken(cookie).Hash()
}

// seenDevice notes the visit. A failed lookup counts as new, a mail too many beats a missed one.
func (s *Service) seenDevice(ctx context.Context, userID, key string) bool {
	_, err := s.conn.Tenant().SeenKnownDevice(ctx, &db.SeenKnownDeviceParams{UserID: userID, Key: key, Now: s.now()})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		slog.Error("failed to look up known devices", "error", err)
	}
	return err == nil
}

// addDevice remembers a new device and mails the account. userAgent arrives cleaned for storage. The mail gets ip as
// it came, only the row takes it cleaned. name is what the mail calls the device.
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

// ForgetDevice only reaches the caller's own devices. The next sign-in from that device is mailed again.
func (s *Service) ForgetDevice(ctx context.Context, id string) error {
	if _, err := uuid.Parse(id); err != nil {
		return nil
	}
	return s.conn.Tenant().
		DeleteKnownDevice(ctx, &db.DeleteKnownDeviceParams{UserID: actor.UserIDFromContext(ctx), ID: id})
}

// verifyToken only finds tokens of the request's workspace. A token of another kind, a bad checksum or an older
// format fails before any lookup.
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
		_ = s.deleteToken(ctx, tok.ID)
		return db.AccessToken{}, errSessionExpired
	}
	return *tok, nil
}

// noteSeen never fails the request, the stamp is only what the lists show.
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

func (s *Service) deleteToken(ctx context.Context, id string) error {
	return s.conn.Tenant().DeleteAccessToken(ctx, id)
}

func (s *Service) ListSessions(ctx context.Context) ([]*db.AccessToken, error) {
	userID := actor.UserIDFromContext(ctx)
	if userID == "" {
		return nil, nil
	}
	return s.conn.Tenant().ListUserSessions(ctx, userID)
}

// Logout needs the DPoP proof for header tokens, so a leaked token alone cannot end a session. A key is no session.
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
	if err := s.deleteToken(ctx, tok.ID); err != nil {
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

// touchCredential never fails the sign-in, "last used" is only a hint for the owner.
func (s *Service) touchCredential(ctx context.Context, id string) {
	err := s.conn.Tenant().TouchCredential(ctx, id)
	if err != nil {
		slog.Warn("failed to mark credential used", "error", err)
	}
}

// recentSignIn is how old a browser session may be for a call marked fresh, like handing out a credential.
const recentSignIn = 10 * time.Minute

// errSignInAgain is a session too old for what it asked. RequireRecentSignIn has ended it already.
var errSignInAgain = errors.New("sign in again to continue")

// FreshFor is how long a session can still make calls marked fresh. nk never can.
func (s *Service) FreshFor(tok *db.AccessToken) time.Duration {
	if tok.Kind != string(actor.KindUser) {
		return 0
	}
	return max(0, recentSignIn-s.now().Sub(tok.CreatedAt))
}

// RequireRecentSignIn takes a fresh browser session, so a stolen cookie cannot become a lasting passkey or a new
// address. An old one ends here, so the sign-in page lets the browser in again instead of sending it straight back.
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
