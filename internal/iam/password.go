package iam

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/argon2"

	"github.com/nokku-sh/nokku/internal/db"
)

// dummyPassword is the candidate the unknown-email and passwordless paths
// verify against, so they cost the same argon2id work as a real check.
//
// #nosec G101 -- a throwaway candidate, not a credential
const dummyPassword = "nokku-dummy-password-do-not-use"

// PasswordParams are the argon2id parameters used for hashing. Memory is in KiB.
type PasswordParams struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	SaltLen uint32
	KeyLen  uint32
}

// DefaultPasswordParams returns production-grade argon2id parameters.
func DefaultPasswordParams() PasswordParams {
	return PasswordParams{
		Time:    3,
		Memory:  64 * 1024,
		Threads: 2,
		SaltLen: 16,
		KeyLen:  32,
	}
}

// PasswordManager hashes and verifies passwords against the unified
// credentials table.
type PasswordManager struct {
	svc    *Service
	params PasswordParams
	// dummy builds the constant-work hash lazily and once, from the same
	// params real checks use, so an unknown email and a wrong password burn
	// identical work even when the host overrides the defaults.
	dummy func() string
}

func newPasswordManager(svc *Service, params PasswordParams) *PasswordManager {
	if params == (PasswordParams{}) {
		params = DefaultPasswordParams()
	}
	m := &PasswordManager{svc: svc, params: params}
	m.dummy = sync.OnceValue(func() string {
		h, err := hashPassword(dummyPassword, m.params)
		if err != nil {
			// Only reachable when crypto/rand fails; the login still fails
			// closed, it just skips the timing equalization.
			return ""
		}
		return h
	})
	return m
}

// Login returns the user matching email if the password verifies, or
// ErrInvalidCredentials. An unknown email costs the same argon2id work as a
// wrong password, so latency does not reveal whether the account exists.
func (m *PasswordManager) Login(ctx context.Context, email, pw string) (*db.User, *http.Cookie, error) {
	email = normalizeEmail(email)
	u, err := m.svc.q.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Burn the same argon2id work as a real check.
			m.burn(pw)
			m.svc.record(
				ctx,
				Event{
					Action: ActionLoginDenied,
					Method: MethodPassword,
					Email:  email,
					Detail: "unknown email",
				},
			)
			return nil, nil, ErrInvalidCredentials
		}
		return nil, nil, err
	}
	if err := m.CheckPassword(ctx, u.ID, pw); err != nil {
		return nil, nil, err
	}
	if err := m.svc.enforceSSO(ctx, email); err != nil {
		return nil, nil, err
	}
	if !u.Active {
		m.svc.record(
			ctx,
			Event{
				Action: ActionLoginDenied,
				Method: MethodPassword,
				UserID: u.ID,
				Email:  u.Email,
				Detail: "inactive",
			},
		)
		return nil, nil, ErrInactive
	}
	if !u.EmailVerified {
		m.svc.record(
			ctx,
			Event{
				Action: ActionLoginDenied,
				Method: MethodPassword,
				UserID: u.ID,
				Email:  u.Email,
				Detail: "unverified email",
			},
		)
		return nil, nil, ErrEmailUnverified
	}
	cookie, err := m.svc.completeLogin(ctx, u, MethodPassword)
	if err != nil {
		return nil, nil, err
	}
	return u, cookie, nil
}

// CheckPassword verifies pw against the user's stored password credential.
func (m *PasswordManager) CheckPassword(ctx context.Context, userID, pw string) error {
	creds, err := m.svc.q.ListCredentialsByType(ctx, &db.ListCredentialsByTypeParams{
		UserID: userID,
		Type:   string(MethodPassword),
	})
	if err != nil {
		return err
	}
	if len(creds) == 0 {
		// A passwordless account must cost the same argon2id work as a wrong
		// password, so latency does not reveal which case occurred.
		m.burn(pw)
		m.svc.record(
			ctx,
			Event{
				Action: ActionLoginDenied,
				Method: MethodPassword,
				UserID: userID,
				Detail: "passwordless",
			},
		)
		return ErrInvalidCredentials
	}

	encoded := string(creds[0].Data)
	ok, err := verifyPassword(pw, encoded)
	if err != nil || !ok {
		m.svc.record(
			ctx,
			Event{
				Action: ActionLoginDenied,
				Method: MethodPassword,
				UserID: userID,
				Detail: "wrong password",
			},
		)
		return ErrInvalidCredentials
	}
	if needsRehash(encoded, m.params) {
		_ = m.store(ctx, userID, pw)
	}
	return nil
}

// enforceSSO rejects the login when the email's verified domain binds a
// provider with SSO enforcement on.
func (s *Service) enforceSSO(ctx context.Context, email string) error {
	d, err := s.GetVerifiedTenantDomain(ctx, emailDomain(email))
	if err != nil {
		return nil // no binding: password login is fine
	}
	p, err := s.GetSSOProvider(ctx, d.ProviderID)
	if err != nil {
		return nil
	}
	enforced := (p.OIDC != nil && p.OIDC.EnforceSSO) ||
		(p.OAuth2 != nil && p.OAuth2.EnforceSSO) ||
		(p.SAML != nil && p.SAML.EnforceSSO)
	if enforced {
		s.record(
			ctx,
			Event{
				Action: ActionLoginDenied,
				Method: MethodPassword,
				Email:  email,
				Detail: "sso enforced",
			},
		)
		return ErrSSORequired
	}
	return nil
}

// HasPassword reports whether the user has a password credential.
func (m *PasswordManager) HasPassword(ctx context.Context, userID string) (bool, error) {
	creds, err := m.svc.q.ListCredentialsByType(ctx, &db.ListCredentialsByTypeParams{
		UserID: userID,
		Type:   string(MethodPassword),
	})
	if err != nil {
		return false, err
	}
	return len(creds) > 0, nil
}

// SetPassword creates or replaces the user's password credential and revokes
// every session of the user, so a stolen session cannot outlive a password
// change or reset.
func (m *PasswordManager) SetPassword(ctx context.Context, userID, pw string) error {
	if err := m.store(ctx, userID, pw); err != nil {
		return err
	}
	if _, err := m.svc.q.DeleteSubjectSessions(ctx, userID); err != nil {
		// Report revocation failure rather than silently leaving stale sessions.
		return err
	}
	m.svc.record(ctx, Event{Action: ActionPasswordSet, Method: MethodPassword, UserID: userID})
	return nil
}

// DeletePassword removes the user's password credential, leaving other
// methods (passkeys, SSO) intact.
func (m *PasswordManager) DeletePassword(ctx context.Context, userID string) error {
	creds, err := m.svc.q.ListCredentialsByType(ctx, &db.ListCredentialsByTypeParams{
		UserID: userID,
		Type:   string(MethodPassword),
	})
	if err != nil {
		return err
	}
	for _, c := range creds {
		if err := m.svc.q.DeleteCredential(
			ctx,
			&db.DeleteCredentialParams{UserID: userID, ID: c.ID},
		); err != nil {
			return err
		}
	}
	return nil
}

// store persists a new password hash without revoking sessions, so
// rehash-on-login does not end the session the user just authenticated with.
func (m *PasswordManager) store(ctx context.Context, userID, pw string) error {
	encoded, err := hashPassword(pw, m.params)
	if err != nil {
		return err
	}

	cred := db.UpsertCredentialParams{
		ID:     userID + ":password",
		UserID: userID,
		Type:   string(MethodPassword),
		Data:   []byte(encoded),
	}
	if existing, err := m.svc.q.ListCredentialsByType(ctx, &db.ListCredentialsByTypeParams{
		UserID: userID,
		Type:   string(MethodPassword),
	}); err == nil && len(existing) > 0 {
		cred.ID = existing[0].ID
	}
	_, err = m.svc.q.UpsertCredential(ctx, &cred)
	return err
}

// Store persists a new password hash without revoking sessions; pair with
// Sessions.RevokeOtherSessions when the current session must survive.
func (m *PasswordManager) Store(ctx context.Context, userID, pw string) error {
	return m.store(ctx, userID, pw)
}

// burn runs one argon2id verification against the dummy hash.
func (m *PasswordManager) burn(password string) {
	if h := m.dummy(); h != "" {
		_, _ = verifyPassword(password, h)
	}
}

// normalizeEmail lowercases and trims, matching the schema's
// email = lower(email) check.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// hashPassword derives an argon2id hash for password and encodes it in PHC
// string format: $argon2id$v=19$m=...,t=...,p=...$salt$hash.
func hashPassword(password string, p PasswordParams) (string, error) {
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		p.Memory,
		p.Time,
		p.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// verifyPassword reports whether password matches the encoded hash.
func verifyPassword(password, encoded string) (bool, error) {
	p, salt, key, err := decodeHash(encoded)
	if err != nil {
		return false, err
	}
	other := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	return subtle.ConstantTimeCompare(key, other) == 1, nil
}

// needsRehash reports whether encoded was derived with different parameters
// than p, meaning it should be rehashed on the next successful login.
func needsRehash(encoded string, p PasswordParams) bool {
	got, _, _, err := decodeHash(encoded)
	if err != nil {
		return true
	}
	return got.Time != p.Time ||
		got.Memory != p.Memory ||
		got.Threads != p.Threads ||
		got.SaltLen != p.SaltLen ||
		got.KeyLen != p.KeyLen
}

func decodeHash(encoded string) (PasswordParams, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return PasswordParams{}, nil, nil, errors.New("iam: invalid hash format")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return PasswordParams{}, nil, nil, errors.New("iam: incompatible argon2 version")
	}

	var p PasswordParams
	if _, err := fmt.Sscanf(
		parts[3],
		"m=%d,t=%d,p=%d",
		&p.Memory,
		&p.Time,
		&p.Threads,
	); err != nil {
		return PasswordParams{}, nil, nil, errors.New("iam: invalid parameters")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return PasswordParams{}, nil, nil, errors.New("iam: invalid salt")
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return PasswordParams{}, nil, nil, errors.New("iam: invalid hash")
	}

	p.SaltLen = uint32(len(salt)) // #nosec G115 -- decoded salt and key are small, bounded slices.
	p.KeyLen = uint32(len(key))   // #nosec G115 -- decoded salt and key are small, bounded slices.
	return p, salt, key, nil
}

// mapUserError translates a duplicate-email insert into ErrEmailTaken.
func mapUserError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
		return ErrEmailTaken
	}
	return err
}
