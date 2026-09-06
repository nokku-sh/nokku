package iam

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
)

const (
	sessionTTL = 168 * time.Hour
)

// SessionHash is the hex token hash a sessions listing exposes as the
// session ID; it is the only session identifier that ever leaves the server.
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
	// TTL is the session lifetime. Zero means the session never expires.
	// The caller must revoke it explicitly.
	TTL time.Duration
}

// IssueSession creates a session and returns it together with the raw token. The
// raw token must be delivered to the client (cookie or body) exactly once.
func (s *Service) IssueSession(ctx context.Context, p SessionParams) (db.Session, string, error) {
	token, err := crypto.RandomString(32)
	if err != nil {
		return db.Session{}, "", err
	}
	tokenHash, err := crypto.HashToken(token)
	if err != nil {
		return db.Session{}, "", err
	}
	if p.Kind == "" {
		p.Kind = KindUser
	}

	now := s.now()
	row := db.Session{
		TokenHash:  tokenHash,
		SubjectID:  p.SubjectID,
		Kind:       string(p.Kind),
		Method:     string(p.Method),
		Binding:    p.Binding,
		Label:      p.Label,
		LastSeenAt: &now,
		CreatedAt:  now,
	}
	if p.WorkspaceID != "" {
		row.WorkspaceID = &p.WorkspaceID
	}
	if p.TTL > 0 {
		expires := now.Add(p.TTL)
		row.ExpiresAt = &expires
	}

	if err := s.q.CreateSession(ctx, &db.CreateSessionParams{
		TokenHash:   row.TokenHash,
		SubjectID:   row.SubjectID,
		Kind:        row.Kind,
		Method:      row.Method,
		WorkspaceID: row.WorkspaceID,
		Binding:     row.Binding,
		Label:       row.Label,
		ExpiresAt:   row.ExpiresAt,
		LastSeenAt:  row.LastSeenAt,
	}); err != nil {
		return db.Session{}, "", err
	}

	s.record(ctx, Event{
		Action:      ActionSessionIssued,
		Kind:        p.Kind,
		Method:      p.Method,
		UserID:      p.SubjectID,
		WorkspaceID: p.WorkspaceID,
	})
	return row, token, nil
}

// VerifySession loads and validates the session for token. It enforces the absolute
// expiry and, when configured, the idle timeout, and refreshes LastSeenAt so
// activity extends the idle window. The refresh is best-effort: a store that
// cannot update it still authenticates.
func (s *Service) VerifySession(ctx context.Context, token string) (db.Session, error) {
	if token == "" {
		return db.Session{}, ErrNoSession
	}
	tokenHash, err := crypto.HashToken(token)
	if err != nil {
		return db.Session{}, err
	}
	sess, err := s.q.GetSession(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.Session{}, ErrNoSession
		}
		return db.Session{}, err
	}

	now := s.now()
	if sess.ExpiresAt != nil && !sess.ExpiresAt.After(now) {
		_ = s.q.DeleteSession(ctx, sess.TokenHash)
		return db.Session{}, ErrSessionExpired
	}

	return *sess, nil
}

// TouchSession refreshes a session's last-seen time unconditionally. Verify's
// refresh is throttled by the idle timeout, which may be zero; this one
// backs surfaces that want an accurate "last active" regardless, such as
// the remembered-device handshake on login.
func (s *Service) TouchSession(ctx context.Context, tokenHash SessionHash) error {
	now := s.now()
	return s.q.TouchSession(
		ctx,
		&db.TouchSessionParams{TokenHash: crypto.HashedToken(tokenHash), LastSeenAt: &now},
	)
}

// ListSessions returns every live session of the subject, newest activity first. It
// backs "your devices" UIs. Expired sessions are pruned opportunistically
// by the hygiene job, not here.
func (s *Service) ListSessions(ctx context.Context, subjectID string) ([]db.Session, error) {
	rows, err := s.q.ListSessionsBySubject(ctx, subjectID)
	if err != nil {
		return nil, err
	}
	sessions := make([]db.Session, 0, len(rows))
	for _, r := range rows {
		sessions = append(sessions, *r)
	}
	slices.SortFunc(sessions, func(a, b db.Session) int {
		return lastSeen(b).Compare(lastSeen(a))
	})
	return sessions, nil
}

// RevokeSession deletes the session identified by the raw token.
func (s *Service) RevokeSession(ctx context.Context, token string) error {
	tokenHash, err := crypto.HashToken(token)
	if err != nil {
		return err
	}
	if err := s.q.DeleteSession(ctx, tokenHash); err != nil {
		return err
	}
	s.record(ctx, Event{Action: ActionSessionRevoked})
	return nil
}

// RevokeSubject deletes every session of the subject and reports how many
// were removed. Used when a password changes or an account is deactivated.
func (s *Service) RevokeSubject(ctx context.Context, subjectID string) (int64, error) {
	return s.q.DeleteSubjectSessions(ctx, subjectID)
}

// RevokeOtherSessions deletes every session of the subject except keep and
// reports how many were removed. The current session survives a deliberate
// password change; everything else dies (NIST 800-63B).
func (s *Service) RevokeOtherSessions(
	ctx context.Context,
	subjectID string,
	keep SessionHash,
) (int64, error) {
	return s.q.DeleteSessionsExcept(ctx, &db.DeleteSessionsExceptParams{
		SubjectID: subjectID,
		KeepHash:  crypto.HashedToken(keep),
	})
}

// DeleteSessionByHash removes a session by its token hash, the ID the
// sessions listing exposes.
func (s *Service) DeleteSessionByHash(ctx context.Context, hash SessionHash) error {
	return s.q.DeleteSession(ctx, crypto.HashedToken(hash))
}

// DeleteExpired prunes expired sessions and reports how many went. It backs
// a hygiene job.
func (s *Service) DeleteExpired(ctx context.Context) (int64, error) {
	now := s.now()
	return s.q.DeleteExpiredSessions(ctx, &now)
}

// lastSeen tolerates a NULL last_seen_at for sorting.
func lastSeen(s db.Session) time.Time {
	if s.LastSeenAt == nil {
		return time.Time{}
	}
	return *s.LastSeenAt
}
