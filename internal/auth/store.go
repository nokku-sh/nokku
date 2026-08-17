package auth

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/mizuchilabs/kagi"

	"github.com/nokku-sh/nokku/internal/db"
)

// Store adapts nokku's database to kagi.Store and kagi.APIKeyStore.
//
// nokku's identity model is global: users, credentials, sessions, and API keys
// are not workspace-scoped (none of their tables are RLS-enforced), so every
// method ignores kagi's tenant parameter and operates on the global tables.
// The tenant dimension matters only to kagi's Policy hooks (SSO provider
// resolution), which are wired at the Service level, not in this store.
type Store struct {
	conn *db.Connection
}

// NewStore builds a kagi store adapter over the database connection.
func NewStore(conn *db.Connection) *Store { return &Store{conn: conn} }

var (
	_ kagi.Store       = (*Store)(nil)
	_ kagi.APIKeyStore = (*Store)(nil)
)

// UserStore ------------------------------------------------------------------

func (s *Store) CreateUser(ctx context.Context, _ kagi.TenantID, u kagi.User) (kagi.User, error) {
	row, err := s.conn.Q.CreateUser(ctx, &db.CreateUserParams{
		Name:     u.DisplayName,
		Username: usernameFromEmail(u.Email),
		Email:    u.Email,
	})
	if err != nil {
		return kagi.User{}, err
	}
	return kagiUser(row), nil
}

// UsernameFromEmail derives a username from an email's local part. nokku does
// not use usernames for login (email is the identity), but the column exists.
func UsernameFromEmail(email string) string {
	return usernameFromEmail(email)
}

// DeleteProviderCredentials deletes every credential of the given type and
// provider. It is a nokku-specific extension (not part of kagi.Store), used
// when an enterprise IdP's issuer changes and its stale identity mappings are
// purged.
func (s *Store) DeleteProviderCredentials(
	ctx context.Context,
	provider string,
	typ kagi.CredentialType,
) error {
	return s.conn.Q.DeleteCredentialsByProvider(ctx, &db.DeleteCredentialsByProviderParams{
		Provider: provider,
		Type:     string(typ),
	})
}

// ConsumeCredentialBySubject atomically deletes the credential identified by
// (type, provider, subject, user) and returns it. It is the delete-on-use
// primitive behind single-use backup codes; the user match means a code from
// one account can never be spent by another.
func (s *Store) ConsumeCredentialBySubject(
	ctx context.Context,
	_ kagi.TenantID,
	typ kagi.CredentialType,
	provider, subject, userID string,
) (kagi.Credential, error) {
	row, err := s.conn.Q.ConsumeCredentialBySubject(ctx, &db.ConsumeCredentialBySubjectParams{
		Type:     string(typ),
		Provider: provider,
		Subject:  subject,
		UserID:   userID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return kagi.Credential{}, kagi.ErrNotFound
		}
		return kagi.Credential{}, err
	}
	return kagiCredential(row), nil
}

func (s *Store) GetUser(ctx context.Context, _ kagi.TenantID, id string) (kagi.User, error) {
	row, err := s.conn.Q.GetUserByID(ctx, id)
	if err != nil {
		return kagi.User{}, userErr(err)
	}
	return kagiUser(row), nil
}

func (s *Store) GetUserByEmail(
	ctx context.Context,
	_ kagi.TenantID,
	email string,
) (kagi.User, error) {
	row, err := s.conn.Q.GetUserByEmail(ctx, email)
	if err != nil {
		return kagi.User{}, userErr(err)
	}
	return kagiUser(row), nil
}

func (s *Store) ListUsers(ctx context.Context, _ kagi.TenantID) ([]kagi.User, error) {
	rows, err := s.conn.Q.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]kagi.User, 0, len(rows))
	for _, r := range rows {
		out = append(out, kagiUser(r))
	}
	return out, nil
}

func (s *Store) UpdateUser(ctx context.Context, _ kagi.TenantID, u kagi.User) error {
	name := u.DisplayName
	_, err := s.conn.Q.UpdateUser(ctx, &db.UpdateUserParams{UserID: u.ID, Name: &name})
	return err
}

func (s *Store) DeleteUser(ctx context.Context, _ kagi.TenantID, id string) error {
	return s.conn.Q.DeleteUser(ctx, id)
}

// CredentialStore -------------------------------------------------------------

func (s *Store) ListCredentials(
	ctx context.Context,
	_ kagi.TenantID,
	userID string,
	typ kagi.CredentialType,
) ([]kagi.Credential, error) {
	rows, err := s.conn.Q.ListCredentials(ctx, &db.ListCredentialsParams{
		UserID: userID,
		Type:   string(typ),
	})
	if err != nil {
		return nil, err
	}
	out := make([]kagi.Credential, 0, len(rows))
	for _, r := range rows {
		out = append(out, kagiCredential(r))
	}
	return out, nil
}

func (s *Store) GetCredential(
	ctx context.Context,
	_ kagi.TenantID,
	userID, id string,
) (kagi.Credential, error) {
	row, err := s.conn.Q.GetCredential(ctx, &db.GetCredentialParams{ID: id, UserID: userID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return kagi.Credential{}, kagi.ErrNotFound
		}
		return kagi.Credential{}, err
	}
	return kagiCredential(row), nil
}

func (s *Store) FindCredentialBySubject(
	ctx context.Context,
	_ kagi.TenantID,
	typ kagi.CredentialType,
	provider, subject string,
) (kagi.Credential, error) {
	row, err := s.conn.Q.FindCredentialBySubject(ctx, &db.FindCredentialBySubjectParams{
		Type:     string(typ),
		Provider: provider,
		Subject:  subject,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return kagi.Credential{}, kagi.ErrNotFound
		}
		return kagi.Credential{}, err
	}
	return kagiCredential(row), nil
}

func (s *Store) PutCredential(ctx context.Context, _ kagi.TenantID, c kagi.Credential) error {
	return s.conn.Q.PutCredential(ctx, &db.PutCredentialParams{
		TenantID:  "",
		ID:        c.ID,
		UserID:    c.UserID,
		Type:      string(c.Type),
		Provider:  c.Provider,
		Subject:   c.Subject,
		Data:      c.Data,
		Label:     c.Label,
		CreatedAt: c.CreatedAt,
		UpdatedAt: c.UpdatedAt,
	})
}

func (s *Store) DeleteCredential(
	ctx context.Context,
	_ kagi.TenantID,
	userID, id string,
) error {
	return s.conn.Q.DeleteCredential(ctx, &db.DeleteCredentialParams{ID: id, UserID: userID})
}

// SessionStore ----------------------------------------------------------------

func (s *Store) CreateSession(ctx context.Context, sess kagi.Session) error {
	return s.conn.Q.CreateSession(ctx, &db.CreateSessionParams{
		TokenHash:  sess.TokenHash,
		TenantID:   string(sess.TenantID),
		SubjectID:  sess.SubjectID,
		Kind:       kindOr(sess.Kind, KindUser),
		IdentityID: strPtr(sess.IdentityID),
		Method:     string(sess.Method),
		Binding:    strPtr(sess.Binding),
		ExpiresAt:  timePtr(sess.ExpiresAt),
	})
}

func (s *Store) GetSession(ctx context.Context, tokenHash []byte) (kagi.Session, error) {
	row, err := s.conn.Q.GetSessionByHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return kagi.Session{}, kagi.ErrNotFound
		}
		return kagi.Session{}, err
	}
	return kagiSession(row), nil
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash []byte) error {
	return s.conn.Q.DeleteSessionByHash(ctx, tokenHash)
}

func (s *Store) DeleteSubjectSessions(
	ctx context.Context,
	t kagi.TenantID,
	subjectID string,
) error {
	return s.conn.Q.DeleteSubjectSessions(ctx, &db.DeleteSubjectSessionsParams{
		TenantID:  string(t),
		SubjectID: subjectID,
	})
}

func (s *Store) DeleteIdentitySessions(ctx context.Context, identityID string) error {
	return s.conn.Q.DeleteIdentitySessions(ctx, &identityID)
}

// APIKeyStore -----------------------------------------------------------------

func (s *Store) PutKey(ctx context.Context, k kagi.APIKeyRecord) error {
	scopes := k.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	return s.conn.Q.PutKey(ctx, &db.PutKeyParams{
		KeyID:      k.KeyID,
		TenantID:   string(k.TenantID),
		SubjectID:  k.SubjectID,
		Kind:       kindOr(k.Kind, KindUser),
		SecretHash: k.SecretHash,
		Scopes:     scopes,
		Name:       k.Name,
		ExpiresAt:  timePtr(k.ExpiresAt),
		CreatedAt:  k.CreatedAt,
	})
}

func (s *Store) GetKey(ctx context.Context, keyID string) (kagi.APIKeyRecord, error) {
	row, err := s.conn.Q.GetKey(ctx, keyID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return kagi.APIKeyRecord{}, kagi.ErrNotFound
		}
		return kagi.APIKeyRecord{}, err
	}
	return kagiAPIKey(row), nil
}

func (s *Store) DeleteKey(ctx context.Context, keyID string) error {
	return s.conn.Q.DeleteKey(ctx, keyID)
}

func (s *Store) ListKeys(
	ctx context.Context,
	t kagi.TenantID,
	subjectID string,
) ([]kagi.APIKeyRecord, error) {
	rows, err := s.conn.Q.ListKeys(ctx, &db.ListKeysParams{
		TenantID:  string(t),
		SubjectID: subjectID,
	})
	if err != nil {
		return nil, err
	}
	out := make([]kagi.APIKeyRecord, 0, len(rows))
	for _, r := range rows {
		out = append(out, kagiAPIKey(r))
	}
	return out, nil
}

func (s *Store) ListTenantKeys(ctx context.Context, t kagi.TenantID) ([]kagi.APIKeyRecord, error) {
	rows, err := s.conn.Q.ListTenantKeys(ctx, string(t))
	if err != nil {
		return nil, err
	}
	out := make([]kagi.APIKeyRecord, 0, len(rows))
	for _, r := range rows {
		out = append(out, kagiAPIKey(r))
	}
	return out, nil
}

// Conversions -----------------------------------------------------------------

func kagiUser(u *db.User) kagi.User {
	return kagi.User{ID: u.ID, Email: u.Email, DisplayName: u.Name}
}

func kagiCredential(c *db.Credential) kagi.Credential {
	return kagi.Credential{
		ID:        c.ID,
		UserID:    c.UserID,
		Type:      kagi.CredentialType(c.Type),
		Provider:  c.Provider,
		Subject:   c.Subject,
		Data:      c.Data,
		Label:     c.Label,
		CreatedAt: c.CreatedAt,
		UpdatedAt: c.UpdatedAt,
	}
}

func kagiSession(row *db.Session) kagi.Session {
	s := kagi.Session{
		TokenHash: row.TokenHash,
		TenantID:  kagi.TenantID(row.TenantID),
		SubjectID: row.SubjectID,
		Kind:      kagi.Kind(row.Kind),
		Method:    kagi.Method(row.Method),
	}
	if row.IdentityID != nil {
		s.IdentityID = *row.IdentityID
	}
	if row.Binding != nil {
		s.Binding = *row.Binding
	}
	if row.ExpiresAt != nil {
		s.ExpiresAt = *row.ExpiresAt
	}
	return s
}

func kagiAPIKey(k *db.APIKey) kagi.APIKeyRecord {
	rec := kagi.APIKeyRecord{
		KeyID:      k.KeyID,
		TenantID:   kagi.TenantID(k.TenantID),
		SubjectID:  k.SubjectID,
		Kind:       kagi.Kind(k.Kind),
		SecretHash: k.SecretHash,
		Scopes:     k.Scopes,
		Name:       k.Name,
		CreatedAt:  k.CreatedAt,
	}
	if k.ExpiresAt != nil {
		rec.ExpiresAt = *k.ExpiresAt
	}
	return rec
}

// Helpers ---------------------------------------------------------------------

func userErr(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return kagi.ErrNotFound
	}
	return err
}

func kindOr(k kagi.Kind, def kagi.Kind) string {
	if k == "" {
		return string(def)
	}
	return string(k)
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func usernameFromEmail(email string) string {
	local, _, ok := strings.Cut(email, "@")
	if !ok {
		local = email
	}
	local = strings.ToLower(local)
	var b strings.Builder
	for _, r := range local {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "user"
	}
	return b.String()
}
