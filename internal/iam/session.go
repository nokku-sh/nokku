package iam

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/util"
)

const (
	// The remembered-device cookie is a handle that powers the sessions list
	// and new-login alerts. It is never an API credential.
	webDeviceCookieName = "nokku_device"
	webDeviceTTL        = 180 * 24 * time.Hour
)

// SessionHash is the hex token hash a sessions listing exposes as the
// session ID. It is the only session identifier that ever leaves the server.
type SessionHash string

type SessionParams struct {
	SubjectID   string
	Kind        Kind
	Method      Method
	WorkspaceID string
	// Binding is the DPoP key thumbprint (jkt) to bind the token to. Empty
	// for cookie sessions.
	Binding string
	// Label names the device for "your devices" listings.
	Label string
	// TTL is the session lifetime. Zero means the session never expires and
	// must be revoked explicitly.
	TTL time.Duration
}

// IssueSession creates a session and returns it with the raw token. The raw
// token must be delivered to the client exactly once.
func (s *Service) IssueSession(ctx context.Context, p SessionParams) (*db.Session, string, error) {
	token, tokenHash, err := crypto.NewSecret()
	if err != nil {
		return nil, "", err
	}
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
	if p.WorkspaceID != "" {
		params.WorkspaceID = &p.WorkspaceID
	}
	if p.TTL > 0 {
		params.ExpiresAt = new(now.Add(p.TTL))
	}
	sess, err := s.sys.CreateSession(ctx, params)
	if err != nil {
		return nil, "", err
	}
	s.record(ctx, Event{
		Action:      ActionSessionIssued,
		Kind:        p.Kind,
		Method:      p.Method,
		UserID:      p.SubjectID,
		WorkspaceID: p.WorkspaceID,
	})
	return sess, token, nil
}

// completeLogin finishes a verified interactive login: it applies the
// account gates every method shares, issues the user session, and returns
// the session cookie. The session stays unpinned: users are global and act
// per request in a workspace.
func (s *Service) completeLogin(ctx context.Context, u *db.User, method Method) (*http.Cookie, error) {
	deny := func(err error, detail string) (*http.Cookie, error) {
		s.record(ctx, Event{
			Action: ActionLoginDenied,
			Method: method,
			UserID: u.ID,
			Email:  u.Email,
			Detail: detail,
		})
		return nil, err
	}
	if !u.Active {
		return deny(ErrInactive, "inactive")
	}
	if !u.EmailVerified {
		return deny(ErrEmailUnverified, "unverified email")
	}
	if !isSSOMethod(method) {
		if err := s.enforceSSO(ctx, u.Email); err != nil {
			return deny(err, "sso enforced")
		}
	}
	sess, token, err := s.IssueSession(ctx, SessionParams{
		SubjectID: u.ID,
		Kind:      KindUser,
		Method:    method,
		TTL:       sessionTTL,
	})
	if err != nil {
		return nil, err
	}
	s.record(ctx, Event{
		Action: ActionLoginSucceeded,
		Kind:   KindUser,
		Method: method,
		UserID: u.ID,
		Email:  u.Email,
	})
	return s.newCookie(sessionCookieName, token, *sess.ExpiresAt), nil
}

// IssueDaemonSession issues the daemon's control-plane token. It never
// expires. Deleting the daemon revokes it.
func (s *Service) IssueDaemonSession(ctx context.Context, workspaceID, daemonID, binding string) (string, error) {
	_, token, err := s.IssueSession(ctx, SessionParams{
		WorkspaceID: workspaceID,
		SubjectID:   daemonID,
		Kind:        KindDaemon,
		Method:      MethodDevice,
		Binding:     binding,
	})
	return token, err
}

// RememberDevice refreshes the remembered-device session when the login
// request carries its cookie, otherwise issues a first one and fires
// OnNewDeviceLogin. It returns the cookie to set, nil for a known device.
func (s *Service) RememberDevice(ctx context.Context, header http.Header, remoteAddr string, u *db.User) *http.Cookie {
	if raw := cookieFromHeader(header, webDeviceCookieName); raw != "" {
		if sess, err := s.VerifySession(ctx, raw); err == nil &&
			sess.Kind == string(KindWebDevice) && sess.SubjectID == u.ID {
			now := s.now()
			if err := s.sys.TouchSession(
				ctx,
				&db.TouchSessionParams{TokenHash: sess.TokenHash, LastSeenAt: &now},
			); err != nil {
				slog.Debug("failed to touch device session", "error", err)
			}
			return nil
		}
	}

	name := deviceNameFromUA(header.Get("User-Agent"))
	sess, token, err := s.IssueSession(ctx, SessionParams{
		SubjectID: u.ID,
		Kind:      KindWebDevice,
		Method:    MethodDevice,
		Label:     name,
		TTL:       webDeviceTTL,
	})
	if err != nil {
		slog.Error("failed to register device session", "error", err)
		return nil
	}
	if s.OnNewDeviceLogin != nil {
		ip := util.GetRemoteIP(header, remoteAddr)
		go s.OnNewDeviceLogin(context.WithoutCancel(ctx), u, sess, name, ip)
	}
	return s.newCookie(webDeviceCookieName, token, *sess.ExpiresAt)
}

// VerifySession loads the session for token and enforces its expiry. An
// expired session is deleted before the error returns.
func (s *Service) VerifySession(ctx context.Context, token string) (db.Session, error) {
	if token == "" {
		return db.Session{}, ErrNoSession
	}
	tokenHash, err := crypto.HashToken(token)
	if err != nil {
		return db.Session{}, err
	}
	sess, err := s.sys.GetSession(ctx, tokenHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return db.Session{}, ErrNoSession
	}
	if err != nil {
		return db.Session{}, err
	}
	if sess.ExpiresAt != nil && !sess.ExpiresAt.After(s.now()) {
		_ = s.sys.DeleteSession(ctx, sess.TokenHash)
		return db.Session{}, ErrSessionExpired
	}
	return *sess, nil
}

// ListSessions returns every session of the request user, newest activity
// first. It backs the "your devices" list.
func (s *Service) ListSessions(ctx context.Context) ([]*db.Session, error) {
	var rows []*db.Session
	err := s.asSelf(ctx, func(q *db.Queries) (err error) {
		rows, err = q.ListSessionsBySubject(ctx, UserIDFromContext(ctx))
		return err
	})
	return rows, err
}

// Logout revokes the session behind the request credential. A header token
// only counts with its DPoP proof, so a leaked token alone cannot end
// someone's session. Service-account keys have no session to revoke. An
// unknown or expired credential is already gone, so only a proof the
// client can fix by re-signing (ErrDPoPNonce, ErrDPoPRequired) fails.
func (s *Service) Logout(ctx context.Context, header http.Header, procedure string) error {
	p, sess, err := s.Authenticate(ctx, header, procedure)
	if errors.Is(err, ErrDPoPNonce) || errors.Is(err, ErrDPoPRequired) {
		return err
	}
	if err != nil || sess.TokenHash == "" {
		return nil
	}
	if err := s.sys.DeleteSession(ctx, sess.TokenHash); err != nil {
		return err
	}
	s.record(ctx, Event{Action: ActionSessionRevoked, Kind: p.Kind, Method: Method(sess.Method), UserID: p.ID})
	return nil
}

// RevokeSubject deletes every session of the subject and reports how many
// went. Used when an account is deactivated.
func (s *Service) RevokeSubject(ctx context.Context, subjectID string) (int64, error) {
	return s.sys.DeleteSubjectSessions(ctx, subjectID)
}

// RevokeOtherSessions deletes every session of the request user except keep
// and reports how many went. The current session survives a deliberate
// password change, everything else dies (NIST 800-63B).
func (s *Service) RevokeOtherSessions(ctx context.Context, keep SessionHash) (int64, error) {
	var n int64
	err := s.asSelf(ctx, func(q *db.Queries) (err error) {
		n, err = q.DeleteSessionsExcept(ctx, &db.DeleteSessionsExceptParams{
			SubjectID: UserIDFromContext(ctx),
			KeepHash:  crypto.HashedToken(keep),
		})
		return err
	})
	return n, err
}

// DeleteOwnSession removes one of the request user's sessions by the hash
// the sessions listing exposes. Other users' sessions are invisible to it.
func (s *Service) DeleteOwnSession(ctx context.Context, hash SessionHash) error {
	return s.asSelf(ctx, func(q *db.Queries) error {
		return q.DeleteSession(ctx, crypto.HashedToken(hash))
	})
}

// DeleteExpired prunes expired sessions and reports how many went. It backs
// a hygiene job.
func (s *Service) DeleteExpired(ctx context.Context) (int64, error) {
	return s.sys.DeleteExpiredSessions(ctx, new(s.now()))
}
