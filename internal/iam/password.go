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

	"github.com/jackc/pgx/v5"
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
	u, err := m.svc.sys.GetUserByEmail(ctx, email)
	if errors.Is(err, pgx.ErrNoRows) {
		m.burn(pw)
		m.svc.record(
			ctx,
			Event{Action: ActionLoginDenied, Method: MethodPassword, Email: email, Detail: "unknown email"},
		)
		return nil, nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, nil, err
	}
	if err := m.CheckPassword(ctx, u.ID, pw); err != nil {
		return nil, nil, err
	}
	cookie, err := m.svc.completeLogin(ctx, u, MethodPassword)
	if err != nil {
		return nil, nil, err
	}
	return u, cookie, nil
}

// CheckPassword verifies pw against the user's stored password credential.
func (m *PasswordManager) CheckPassword(ctx context.Context, userID, pw string) error {
	denied := func(detail string) error {
		m.svc.record(ctx, Event{Action: ActionLoginDenied, Method: MethodPassword, UserID: userID, Detail: detail})
		return ErrInvalidCredentials
	}
	cred, err := m.svc.sys.GetCredential(ctx, &db.GetCredentialParams{UserID: userID, ID: passwordCredentialID(userID)})
	if errors.Is(err, pgx.ErrNoRows) {
		// A passwordless account costs the same work as a wrong password.
		m.burn(pw)
		return denied("passwordless")
	}
	if err != nil {
		return err
	}
	encoded := string(cred.Data)
	if ok, err := verifyPassword(pw, encoded); err != nil || !ok {
		return denied("wrong password")
	}
	if needsRehash(encoded, m.params) {
		_ = m.Store(ctx, userID, pw)
	}
	return nil
}

// HasPassword reports whether the user has a password credential.
func (m *PasswordManager) HasPassword(ctx context.Context, userID string) (bool, error) {
	_, err := m.svc.sys.GetCredential(ctx, &db.GetCredentialParams{UserID: userID, ID: passwordCredentialID(userID)})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// SetPassword replaces the user's password and revokes every session of the
// user, so a stolen session cannot outlive a reset.
func (m *PasswordManager) SetPassword(ctx context.Context, userID, pw string) error {
	if err := m.Store(ctx, userID, pw); err != nil {
		return err
	}
	if _, err := m.svc.sys.DeleteSubjectSessions(ctx, userID); err != nil {
		return err
	}
	m.svc.record(ctx, Event{Action: ActionPasswordSet, Method: MethodPassword, UserID: userID})
	return nil
}

// DeletePassword removes the user's password credential, leaving other
// methods intact.
func (m *PasswordManager) DeletePassword(ctx context.Context, userID string) error {
	return m.svc.sys.DeleteCredential(ctx, &db.DeleteCredentialParams{UserID: userID, ID: passwordCredentialID(userID)})
}

// Store persists a new password hash without revoking sessions. Pair it
// with RevokeOtherSessions when the current session must survive.
func (m *PasswordManager) Store(ctx context.Context, userID, pw string) error {
	return m.store(ctx, m.svc.sys, userID, pw)
}

func (m *PasswordManager) store(ctx context.Context, q db.Querier, userID, pw string) error {
	encoded, err := hashPassword(pw, m.params)
	if err != nil {
		return err
	}
	_, err = q.UpsertCredential(ctx, &db.UpsertCredentialParams{
		ID:     passwordCredentialID(userID),
		UserID: userID,
		Type:   string(MethodPassword),
		Data:   []byte(encoded),
	})
	return err
}

func passwordCredentialID(userID string) string {
	return userID + ":password"
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
	if db.IsUniqueViolation(err) {
		return ErrEmailTaken
	}
	return err
}
