package iam

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/util"
)

const (
	// The device cookie powers the sessions list and new-login alerts. It is
	// never an API credential.
	webDeviceCookieName = "nokku_device"
	webDeviceTTL        = 180 * 24 * time.Hour
	// maxUserAgent keeps a hostile header from bloating the sessions table.
	maxUserAgent = 512
)

// SessionHash is the only session identifier that ever leaves the server.
type SessionHash string

type SessionParams struct {
	SubjectID   string
	Kind        actor.Kind
	Method      Method
	WorkspaceID string
	// Binding is the DPoP jkt, empty for cookie sessions.
	Binding string
	Label   string
	// TTL zero never expires, the session must be revoked explicitly.
	TTL time.Duration
}

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
	if meta, ok := RequestMetaFromContext(ctx); ok {
		params.UserAgent = truncate(util.SanitizeUTF8(meta.Header.Get("User-Agent")), maxUserAgent)
		params.Ip = util.SanitizeUTF8(util.GetRemoteIP(meta.Header, meta.RemoteAddr))
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

// completeLogin applies the gates every login method shares. The session
// stays unpinned since users pick a workspace per request.
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
		Kind:      actor.KindUser,
		Method:    method,
		TTL:       sessionTTL,
	})
	if err != nil {
		return nil, err
	}
	s.record(ctx, Event{
		Action: ActionLoginSucceeded,
		Kind:   actor.KindUser,
		Method: method,
		UserID: u.ID,
		Email:  u.Email,
	})
	return s.newCookie(sessionCookieName, token, *sess.ExpiresAt), nil
}

// IssueDaemonSession never expires, deleting the daemon revokes it.
func (s *Service) IssueDaemonSession(ctx context.Context, workspaceID, daemonID, binding string) (string, error) {
	_, token, err := s.IssueSession(ctx, SessionParams{
		WorkspaceID: workspaceID,
		SubjectID:   daemonID,
		Kind:        actor.KindDaemon,
		Method:      MethodDevice,
		Binding:     binding,
	})
	return token, err
}

// RememberDevice returns nil for a known device. A new one gets a cookie and
// fires OnNewDeviceLogin.
func (s *Service) RememberDevice(ctx context.Context, header http.Header, remoteAddr string, u *db.User) *http.Cookie {
	if raw := cookieFromHeader(header, webDeviceCookieName); raw != "" {
		if sess, err := s.VerifySession(ctx, raw); err == nil &&
			sess.Kind == string(actor.KindWebDevice) && sess.SubjectID == u.ID {
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
		Kind:      actor.KindWebDevice,
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

func (s *Service) ListSessions(ctx context.Context) ([]*db.Session, error) {
	var rows []*db.Session
	err := s.asSelf(ctx, func(q *db.Queries) (err error) {
		rows, err = q.ListSessionsBySubject(ctx, actor.UserIDFromContext(ctx))
		return err
	})
	return rows, err
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
	if err := s.sys.DeleteSession(ctx, sess.TokenHash); err != nil {
		return err
	}
	s.record(ctx, Event{Action: ActionSessionRevoked, Kind: p.Kind, Method: Method(sess.Method), UserID: p.ID})
	return nil
}

func (s *Service) RevokeSubject(ctx context.Context, subjectID string) (int64, error) {
	return s.sys.DeleteSubjectSessions(ctx, subjectID)
}

func (s *Service) RevokeOtherSessions(ctx context.Context, keep SessionHash) (int64, error) {
	var n int64
	err := s.asSelf(ctx, func(q *db.Queries) (err error) {
		n, err = q.DeleteSessionsExcept(ctx, &db.DeleteSessionsExceptParams{
			SubjectID: actor.UserIDFromContext(ctx),
			KeepHash:  crypto.HashedToken(keep),
		})
		return err
	})
	return n, err
}

func (s *Service) DeleteOwnSession(ctx context.Context, hash SessionHash) error {
	return s.asSelf(ctx, func(q *db.Queries) error {
		return q.DeleteSession(ctx, crypto.HashedToken(hash))
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
	if err := s.sys.TouchCredential(ctx, id); err != nil {
		slog.Warn("failed to mark credential used", "error", err)
	}
}
