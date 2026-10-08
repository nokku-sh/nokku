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

// SessionHash is the only session identifier that ever leaves the server.
type SessionHash string

type SessionParams struct {
	SubjectID string
	Kind      actor.Kind
	Method    Method
	// Binding is the DPoP jkt, empty for cookie sessions.
	Binding string
	Label   string
	// TTL zero never expires, the session must be revoked explicitly.
	TTL time.Duration
}

// IssueSession pins the session to the request's workspace.
func (s *Service) IssueSession(ctx context.Context, p SessionParams) (*db.Session, string, error) {
	token, tokenHash := crypto.NewSecret()
	now := s.now()
	params := &db.CreateSessionParams{
		TokenHash:  tokenHash,
		SubjectID:  p.SubjectID,
		Kind:       string(p.Kind),
		Method:     string(p.Method),
		Binding:    p.Binding,
		Label:      p.Label,
		LastSeenAt: &now,
	}
	if meta, ok := actor.RequestMetaFromContext(ctx); ok {
		params.UserAgent = truncate(strings.ToValidUTF8(meta.Header.Get("User-Agent"), ""), maxUserAgent)
		params.Ip = strings.ToValidUTF8(realip.Bucket(meta.Header, meta.RemoteAddr), "")
	}
	if p.TTL > 0 {
		params.ExpiresAt = new(now.Add(p.TTL))
	}
	sess, err := s.conn.Tenant().CreateSession(ctx, params)
	if err != nil {
		return nil, "", err
	}
	s.record(ctx, event{Action: actionSessionIssued, Kind: p.Kind, Method: p.Method, UserID: p.SubjectID})
	return sess, token, nil
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
	sess, token, err := s.IssueSession(ctx, SessionParams{
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
	_, token, err := s.IssueSession(ctx, SessionParams{
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

// verifySession only finds sessions of the request's workspace.
func (s *Service) verifySession(ctx context.Context, token string) (db.Session, error) {
	if token == "" {
		return db.Session{}, errNoSession
	}
	tokenHash := crypto.HashToken(token)
	sess, err := s.conn.Tenant().GetSession(ctx, tokenHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return db.Session{}, errNoSession
	}
	if err != nil {
		return db.Session{}, err
	}
	if sess.ExpiresAt != nil && !sess.ExpiresAt.After(s.now()) {
		_ = s.deleteSession(ctx, sess.TokenHash)
		return db.Session{}, errSessionExpired
	}
	return *sess, nil
}

// noteSeen records that an authenticated request used the session. It never
// fails the request, the stamp is only what the sessions list shows.
func (s *Service) noteSeen(ctx context.Context, sess db.Session) {
	now := s.now()
	if sess.LastSeenAt != nil && now.Sub(*sess.LastSeenAt) < sessionSeenEvery {
		return
	}
	err := s.conn.Tenant().TouchSession(ctx, &db.TouchSessionParams{TokenHash: sess.TokenHash, LastSeenAt: &now})
	if err != nil {
		slog.Warn("failed to note session activity", "error", err)
	}
}

func (s *Service) deleteSession(ctx context.Context, hash crypto.HashedToken) error {
	return s.conn.Tenant().DeleteSession(ctx, hash)
}

func (s *Service) ListSessions(ctx context.Context) ([]*db.Session, error) {
	return s.conn.Tenant().ListSessionsBySubject(ctx, actor.UserIDFromContext(ctx))
}

// Logout needs the DPoP proof for header tokens, so a leaked token alone
// cannot end someone's session. Unknown credentials are already gone, so only
// errors fixed by re-signing fail.
func (s *Service) Logout(ctx context.Context, header http.Header, procedure string) error {
	p, sess, err := s.Authenticate(ctx, header, procedure)
	if errors.Is(err, ErrDPoPNonce) || errors.Is(err, ErrDPoPRequired) {
		return err
	}
	if err != nil || sess.TokenHash == "" {
		return nil
	}
	if err := s.deleteSession(ctx, sess.TokenHash); err != nil {
		return err
	}
	s.record(ctx, event{Action: actionSessionRevoked, Kind: p.Kind, Method: Method(sess.Method), UserID: p.ID})
	return nil
}

func (s *Service) revokeSubject(ctx context.Context, subjectID string) (int64, error) {
	return s.conn.Tenant().DeleteSubjectSessions(ctx, subjectID)
}

func (s *Service) RevokeOtherSessions(ctx context.Context, keep SessionHash) (int64, error) {
	return s.conn.Tenant().DeleteSessionsExcept(ctx, &db.DeleteSessionsExceptParams{
		SubjectID: actor.UserIDFromContext(ctx),
		KeepHash:  crypto.HashedToken(keep),
	})
}

// DeleteOwnSession only reaches the caller's own sessions.
func (s *Service) DeleteOwnSession(ctx context.Context, hash SessionHash) error {
	return s.conn.TenantTx(ctx, func(q *db.Queries) error {
		rows, err := q.ListSessionsBySubject(ctx, actor.UserIDFromContext(ctx))
		if err != nil {
			return err
		}
		for _, sess := range rows {
			if sess.TokenHash == crypto.HashedToken(hash) {
				return q.DeleteSession(ctx, sess.TokenHash)
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
