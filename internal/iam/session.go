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
	"github.com/nokku-sh/nokku/internal/realip"
)

const (
	// A device marker remembers a browser by its cookie and a terminal by its
	// signing key, see RememberDevice and rememberTerminal. It powers the
	// sessions list and new-login alerts and is never an API credential.
	deviceCookieName = "nokku_device"
	deviceMarkerTTL  = 180 * 24 * time.Hour
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
		params.UserAgent = truncate(strings.ToValidUTF8(meta.Header.Get("User-Agent"), ""), maxUserAgent)
		params.Ip = strings.ToValidUTF8(realip.Bucket(meta.Header, meta.RemoteAddr), "")
	}
	if p.TTL > 0 {
		params.ExpiresAt = new(now.Add(p.TTL))
	}
	var sess *db.Session
	err = s.inWorkspace(ctx, func(q *db.Queries, ws string) (err error) {
		params.WorkspaceID = ws
		sess, err = q.CreateSession(ctx, params)
		return err
	})
	if err != nil {
		return nil, "", err
	}
	s.record(ctx, Event{Action: ActionSessionIssued, Kind: p.Kind, Method: p.Method, UserID: p.SubjectID})
	return sess, token, nil
}

// completeLogin applies the gates every login method shares.
func (s *Service) completeLogin(ctx context.Context, u *db.User, method Method) (*http.Cookie, error) {
	deny := func(err error, detail string) (*http.Cookie, error) {
		s.record(ctx, Event{Action: ActionLoginDenied, Method: method, UserID: u.ID, Email: u.Email, Detail: detail})
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
		Event{Action: ActionLoginSucceeded, Kind: actor.KindUser, Method: method, UserID: u.ID, Email: u.Email},
	)
	return s.newCookie(sessionCookieName, token, *sess.ExpiresAt), nil
}

func (s *Service) ssoEnforced(ctx context.Context) (bool, error) {
	var enforced bool
	err := s.inWorkspace(ctx, func(q *db.Queries, ws string) error {
		w, err := q.GetWorkspace(ctx, ws)
		if err != nil {
			return err
		}
		enforced = w.Settings.GetEnforceSso()
		return nil
	})
	return enforced, err
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

// RememberDevice returns nil for a known device. A new one gets a cookie and
// fires OnNewDeviceLogin.
func (s *Service) RememberDevice(ctx context.Context, header http.Header, remoteAddr string, u *db.User) *http.Cookie {
	if raw := cookieFromHeader(header, deviceCookieName); raw != "" {
		if sess, err := s.verifySession(ctx, raw); err == nil &&
			sess.Kind == string(actor.KindDevice) && sess.SubjectID == u.ID {
			s.touchSession(ctx, sess.TokenHash)
			return nil
		}
	}

	name := deviceNameFromUA(header.Get("User-Agent"))
	sess, token, err := s.IssueSession(ctx, SessionParams{
		SubjectID: u.ID,
		Kind:      actor.KindDevice,
		Method:    MethodDevice,
		Label:     name,
		TTL:       deviceMarkerTTL,
	})
	if err != nil {
		slog.Error("failed to register device session", "error", err)
		return nil
	}
	if s.OnNewDeviceLogin != nil {
		ip := realip.Bucket(header, remoteAddr)
		go s.OnNewDeviceLogin(context.WithoutCancel(ctx), u, sess, name, ip)
	}
	return s.newCookie(deviceCookieName, token, *sess.ExpiresAt)
}

func (s *Service) touchSession(ctx context.Context, hash crypto.HashedToken) {
	now := s.now()
	// Best effort, last_seen_at is a hint.
	_ = s.inWorkspace(ctx, func(q *db.Queries, ws string) error {
		return q.TouchSession(ctx, &db.TouchSessionParams{WorkspaceID: ws, TokenHash: hash, LastSeenAt: &now})
	})
}

// verifySession only finds sessions of the request's workspace.
func (s *Service) verifySession(ctx context.Context, token string) (db.Session, error) {
	if token == "" {
		return db.Session{}, errNoSession
	}
	tokenHash, err := crypto.HashToken(token)
	if err != nil {
		return db.Session{}, err
	}
	var sess *db.Session
	err = s.inWorkspace(ctx, func(q *db.Queries, ws string) (err error) {
		sess, err = q.GetSession(ctx, &db.GetSessionParams{WorkspaceID: ws, TokenHash: tokenHash})
		return err
	})
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

func (s *Service) deleteSession(ctx context.Context, hash crypto.HashedToken) error {
	return s.inWorkspace(ctx, func(q *db.Queries, ws string) error {
		return q.DeleteSession(ctx, &db.DeleteSessionParams{WorkspaceID: ws, TokenHash: hash})
	})
}

func (s *Service) ListSessions(ctx context.Context) ([]*db.Session, error) {
	var rows []*db.Session
	err := s.inWorkspace(ctx, func(q *db.Queries, ws string) (err error) {
		rows, err = q.ListSessionsBySubject(ctx, &db.ListSessionsBySubjectParams{
			WorkspaceID: ws,
			SubjectID:   actor.UserIDFromContext(ctx),
		})
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
	if err := s.deleteSession(ctx, sess.TokenHash); err != nil {
		return err
	}
	s.record(ctx, Event{Action: ActionSessionRevoked, Kind: p.Kind, Method: Method(sess.Method), UserID: p.ID})
	return nil
}

func (s *Service) revokeSubject(ctx context.Context, subjectID string) (int64, error) {
	var n int64
	err := s.inWorkspace(ctx, func(q *db.Queries, ws string) (err error) {
		n, err = q.DeleteSubjectSessions(ctx, &db.DeleteSubjectSessionsParams{WorkspaceID: ws, SubjectID: subjectID})
		return err
	})
	return n, err
}

func (s *Service) RevokeOtherSessions(ctx context.Context, keep SessionHash) (int64, error) {
	var n int64
	err := s.inWorkspace(ctx, func(q *db.Queries, ws string) (err error) {
		n, err = q.DeleteSessionsExcept(ctx, &db.DeleteSessionsExceptParams{
			WorkspaceID: ws,
			SubjectID:   actor.UserIDFromContext(ctx),
			KeepHash:    crypto.HashedToken(keep),
		})
		return err
	})
	return n, err
}

// DeleteOwnSession only reaches the caller's own sessions.
func (s *Service) DeleteOwnSession(ctx context.Context, hash SessionHash) error {
	return s.inWorkspace(ctx, func(q *db.Queries, ws string) error {
		rows, err := q.ListSessionsBySubject(ctx, &db.ListSessionsBySubjectParams{
			WorkspaceID: ws,
			SubjectID:   actor.UserIDFromContext(ctx),
		})
		if err != nil {
			return err
		}
		for _, sess := range rows {
			if sess.TokenHash == crypto.HashedToken(hash) {
				return q.DeleteSession(ctx, &db.DeleteSessionParams{WorkspaceID: ws, TokenHash: sess.TokenHash})
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
	err := s.inWorkspace(ctx, func(q *db.Queries, ws string) error {
		return q.TouchCredential(ctx, &db.TouchCredentialParams{WorkspaceID: ws, ID: id})
	})
	if err != nil {
		slog.Warn("failed to mark credential used", "error", err)
	}
}
