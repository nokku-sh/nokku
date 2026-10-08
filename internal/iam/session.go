package iam

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/realip"
)

const (
	// A known device is a browser remembered by its cookie or a terminal by
	// its signing key. It shows in the sessions list, and a sign-in from one
	// the account has not used before is mailed. It lives in its own table
	// and never signs anyone in.
	//
	// The cookie is per account, its name ends in the user id. With one name
	// for the browser every account that signs in replaces the cookie of the
	// last one, and each switch counts as a new device.
	deviceCookiePrefix = "nokku_device_"
	deviceTTL          = 180 * 24 * time.Hour
	// maxUserAgent keeps a hostile header from bloating the sessions table.
	maxUserAgent = 512
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
}

// IssueToken pins the token to the request's workspace. The plaintext is
// returned once, only its hash is stored.
func (s *Service) IssueToken(ctx context.Context, p TokenParams) (*db.AccessToken, string, error) {
	token, tokenHash := crypto.NewSecret()
	switch p.Kind {
	case actor.KindServiceAccount:
		token, tokenHash = crypto.NewKey(crypto.KeyPrefixServiceAccount)
	case actor.KindSCIM:
		token, tokenHash = crypto.NewKey(crypto.KeyPrefixSCIM)
	case actor.KindUser, actor.KindCLI, actor.KindDaemon:
	}
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
		params.UserAgent = truncate(strings.ToValidUTF8(meta.Header.Get("User-Agent"), ""), maxUserAgent)
		params.Ip = strings.ToValidUTF8(realip.Bucket(meta.Header, meta.RemoteAddr), "")
	}
	if p.TTL > 0 {
		params.ExpiresAt = new(now.Add(p.TTL))
	}
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

// completeLogin applies the gates every login method shares.
func (s *Service) completeLogin(ctx context.Context, u *db.User, method Method) (*http.Cookie, error) {
	deny := func(err error, detail string) (*http.Cookie, error) {
		s.record(ctx, event{Action: actionLoginDenied, Method: method, UserID: u.ID, Email: u.Email, Detail: detail})
		return nil, err
	}
	if !u.Active {
		return deny(ErrInactive, "inactive")
	}
	if method != MethodOIDC {
		enforced, err := s.ssoEnforced(ctx)
		if err != nil {
			return nil, err
		}
		if enforced {
			return deny(ErrSSORequired, "sso enforced")
		}
	}
	sess, token, err := s.IssueToken(ctx, TokenParams{
		SubjectID: u.ID,
		Kind:      actor.KindUser,
		Method:    method,
		TTL:       sessionTTL,
	})
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

// IssueDaemonSession replaces the daemon's earlier sessions. The session
// never expires. After the daemon is deleted it only gets the REJECTED answer
// from SyncDaemon, which also removes it.
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

// RememberDevice returns nil for a browser the account has signed in from
// before. A new one gets a cookie, and the account a mail.
func (s *Service) RememberDevice(ctx context.Context, header http.Header, remoteAddr string, u *db.User) *http.Cookie {
	name := deviceCookiePrefix + u.ID
	if raw := cookieFromHeader(header, name); raw != "" && s.seenDevice(ctx, u.ID, deviceKey(raw)) {
		return nil
	}
	token := crypto.RandomString(32)
	userAgent := header.Get("User-Agent")
	d, err := s.addDevice(
		ctx,
		u,
		deviceKey(token),
		userAgent,
		deviceNameFromUA(userAgent),
		realip.Bucket(header, remoteAddr),
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

// seenDevice reports whether the account has signed in from the device
// before, and notes the visit. A failed lookup counts as new, a mail too
// many beats a missed one.
func (s *Service) seenDevice(ctx context.Context, userID, key string) bool {
	_, err := s.conn.Tenant().SeenKnownDevice(ctx, &db.SeenKnownDeviceParams{UserID: userID, Key: key, Now: s.now()})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		slog.Error("failed to look up known devices", "error", err)
	}
	return err == nil
}

// addDevice remembers a device the account has not signed in from before
// and mails the account about it. name is what the mail calls the device.
func (s *Service) addDevice(ctx context.Context, u *db.User, key, userAgent, name, ip string) (*db.KnownDevice, error) {
	now := s.now()
	d, err := s.conn.Tenant().AddKnownDevice(ctx, &db.AddKnownDeviceParams{
		UserID:    u.ID,
		Key:       key,
		Ip:        strings.ToValidUTF8(ip, ""),
		UserAgent: truncate(strings.ToValidUTF8(userAgent, ""), maxUserAgent),
		ExpiresAt: now.Add(deviceTTL),
		Now:       now,
	})
	if err != nil {
		return nil, err
	}
	s.notifyNewDevice(ctx, u, d.ID, name, ip)
	return d, nil
}

// ListDevices is every device the signed-in user is remembered on.
func (s *Service) ListDevices(ctx context.Context) ([]*db.KnownDevice, error) {
	return s.conn.Tenant().ListKnownDevices(ctx, actor.UserIDFromContext(ctx))
}

// ForgetDevice only reaches the caller's own devices. The next sign-in from
// that device is mailed again.
func (s *Service) ForgetDevice(ctx context.Context, id string) error {
	if _, err := uuid.Parse(id); err != nil {
		return nil
	}
	return s.conn.Tenant().
		DeleteKnownDevice(ctx, &db.DeleteKnownDeviceParams{UserID: actor.UserIDFromContext(ctx), ID: id})
}

// verifyToken only finds tokens of the request's workspace. A key with a
// bad checksum is a typo or a lookalike, it fails before any lookup.
func (s *Service) verifyToken(ctx context.Context, token string) (db.AccessToken, error) {
	if token == "" {
		return db.AccessToken{}, errNoSession
	}
	if strings.HasPrefix(token, "nk_") && !crypto.CheckKey(token) {
		return db.AccessToken{}, errInvalidCredentials
	}
	tok, err := s.conn.Tenant().GetAccessToken(ctx, crypto.HashToken(token))
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

// noteSeen records that an authenticated request used the token. It never
// fails the request, the stamp is only what the lists show.
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

// ListSessions is the browsers and terminals the signed-in user is on.
func (s *Service) ListSessions(ctx context.Context) ([]*db.AccessToken, error) {
	userID := actor.UserIDFromContext(ctx)
	if userID == "" {
		return nil, nil
	}
	return s.conn.Tenant().ListUserSessions(ctx, userID)
}

// Logout ends a browser or CLI session. It needs the DPoP proof for header
// tokens, so a leaked token alone cannot end someone's session. A key is
// not a session, a script that calls this keeps its key. Unknown credentials
// are already gone, so only errors fixed by re-signing fail.
func (s *Service) Logout(ctx context.Context, header http.Header, procedure string) error {
	p, tok, err := s.Authenticate(ctx, header, procedure)
	if errors.Is(err, ErrDPoPNonce) || errors.Is(err, ErrDPoPRequired) {
		return err
	}
	if err != nil || (p.Kind != actor.KindUser && p.Kind != actor.KindCLI) {
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

// touchCredential marks a credential as used by a sign-in. It never fails
// the sign-in, "last used" is only a hint for the owner.
func (s *Service) touchCredential(ctx context.Context, id string) {
	err := s.conn.Tenant().TouchCredential(ctx, id)
	if err != nil {
		slog.Warn("failed to mark credential used", "error", err)
	}
}
