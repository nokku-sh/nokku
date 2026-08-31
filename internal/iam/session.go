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

// SessionOptions configures session issuance.
type SessionOptions struct {
	// TTL is the default absolute session lifetime for issued sessions.
	TTL time.Duration
	// IdleTimeout, when positive, caps inactivity: a session expires when
	// this much time passes without a request. It is enforced alongside the
	// absolute TTL, whichever comes first. Zero disables the idle check.
	IdleTimeout time.Duration
}

// SessionHash is the hex token hash a sessions listing exposes as the
// session ID; it is the only session identifier that ever leaves the server.
type SessionHash string

// SessionParams parameterizes SessionManager.Issue.
type SessionParams struct {
	SubjectID string
	Kind      Kind
	Method    Method
	// WorkspaceID pins the session to a workspace tenant (daemons); empty
	// means the subject is global.
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

// SessionManager issues and validates opaque session tokens against the
// store. The raw token crosses the wire once; only its SHA-256 hash is
// stored, so a database leak reveals nothing usable.
type SessionManager struct {
	svc  *Service
	opts SessionOptions
}

// Issue creates a session and returns it together with the raw token. The
// raw token must be delivered to the client (cookie or body) exactly once.
func (sm *SessionManager) Issue(ctx context.Context, p SessionParams) (db.Session, string, error) {
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

	now := sm.svc.now()
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

	if err := sm.svc.q.CreateSession(ctx, &db.CreateSessionParams{
		TokenHash:   row.TokenHash,
		SubjectID:   row.SubjectID,
		Kind:        row.Kind,
		Method:      row.Method,
		WorkspaceID: row.WorkspaceID,
		Binding:     row.Binding,
		Label:       row.Label,
		ExpiresAt:   row.ExpiresAt,
	}); err != nil {
		return db.Session{}, "", err
	}

	sm.svc.record(ctx, Event{
		Action:      ActionSessionIssued,
		Kind:        p.Kind,
		Method:      p.Method,
		UserID:      p.SubjectID,
		WorkspaceID: p.WorkspaceID,
	})
	return row, token, nil
}

// Verify loads and validates the session for token. It enforces the absolute
// expiry and, when configured, the idle timeout, and refreshes LastSeenAt so
// activity extends the idle window. The refresh is best-effort: a store that
// cannot update it still authenticates.
func (sm *SessionManager) Verify(ctx context.Context, token string) (db.Session, error) {
	if token == "" {
		return db.Session{}, ErrNoSession
	}
	tokenHash, err := crypto.HashToken(token)
	if err != nil {
		return db.Session{}, err
	}
	s, err := sm.svc.q.GetSession(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.Session{}, ErrNoSession
		}
		return db.Session{}, err
	}

	now := sm.svc.now()
	if s.ExpiresAt != nil && !s.ExpiresAt.After(now) {
		_ = sm.svc.q.DeleteSession(ctx, s.TokenHash)
		return db.Session{}, ErrSessionExpired
	}
	if sm.opts.IdleTimeout > 0 && s.LastSeenAt != nil {
		if now.After(s.LastSeenAt.Add(sm.opts.IdleTimeout)) {
			// Prune the dead session so listings stay honest.
			_ = sm.svc.q.DeleteSession(ctx, s.TokenHash)
			return db.Session{}, ErrSessionExpired
		}
		// Refresh at most twice per idle window so the touch does not turn
		// into a write per request.
		if now.Sub(*s.LastSeenAt) > sm.opts.IdleTimeout/2 {
			_ = sm.svc.q.TouchSession(
				ctx,
				&db.TouchSessionParams{TokenHash: s.TokenHash, LastSeenAt: &now},
			)
			s.LastSeenAt = &now
		}
	}
	return *s, nil
}

// List returns every live session of the subject, newest activity first. It
// backs "your devices" UIs. Expired sessions are pruned opportunistically
// by the hygiene job, not here.
func (sm *SessionManager) List(ctx context.Context, subjectID string) ([]db.Session, error) {
	rows, err := sm.svc.q.ListSessionsBySubject(ctx, subjectID)
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

// Revoke deletes the session identified by the raw token.
func (sm *SessionManager) Revoke(ctx context.Context, token string) error {
	tokenHash, err := crypto.HashToken(token)
	if err != nil {
		return err
	}
	if err := sm.svc.q.DeleteSession(ctx, tokenHash); err != nil {
		return err
	}
	sm.svc.record(ctx, Event{Action: ActionSessionRevoked})
	return nil
}

// RevokeSubject deletes every session of the subject and reports how many
// were removed. Used when a password changes or an account is deactivated.
func (sm *SessionManager) RevokeSubject(ctx context.Context, subjectID string) (int64, error) {
	return sm.svc.q.DeleteSubjectSessions(ctx, subjectID)
}

// RevokeOtherSessions deletes every session of the subject except keep and
// reports how many were removed. The current session survives a deliberate
// password change; everything else dies (NIST 800-63B).
func (sm *SessionManager) RevokeOtherSessions(
	ctx context.Context,
	subjectID string,
	keep SessionHash,
) (int64, error) {
	return sm.svc.q.DeleteSessionsExcept(ctx, &db.DeleteSessionsExceptParams{
		SubjectID: subjectID,
		KeepHash:  crypto.HashedToken(keep),
	})
}

// DeleteSessionByHash removes a session by its token hash, the ID the
// sessions listing exposes.
func (sm *SessionManager) DeleteSessionByHash(ctx context.Context, hash SessionHash) error {
	return sm.svc.q.DeleteSession(ctx, crypto.HashedToken(hash))
}

// DeleteExpired prunes expired sessions and reports how many went. It backs
// a hygiene job.
func (sm *SessionManager) DeleteExpired(ctx context.Context) (int64, error) {
	now := sm.svc.now()
	return sm.svc.q.DeleteExpiredSessions(ctx, &now)
}

// lastSeen tolerates a NULL last_seen_at for sorting.
func lastSeen(s db.Session) time.Time {
	if s.LastSeenAt == nil {
		return time.Time{}
	}
	return *s.LastSeenAt
}
