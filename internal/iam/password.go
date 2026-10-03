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

// dummyPassword makes unknown-email and passwordless checks cost the same
// argon2id work as a real one.
//
// #nosec G101 -- a throwaway candidate, not a credential
const dummyPassword = "nokku-dummy-password-do-not-use"

// hashSlots bounds concurrent argon2 runs. Each one takes 64 MiB, so a burst
// of logins has to queue instead of exhausting memory.
var hashSlots = make(chan struct{}, 4)

func argon2Key(password string, salt []byte, p passwordParams) []byte {
	hashSlots <- struct{}{}
	defer func() { <-hashSlots }()
	return argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
}

// passwordParams Memory is in KiB.
type passwordParams struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	SaltLen uint32
	KeyLen  uint32
}

func defaultPasswordParams() passwordParams {
	return passwordParams{
		Time:    3,
		Memory:  64 * 1024,
		Threads: 2,
		SaltLen: 16,
		KeyLen:  32,
	}
}

type PasswordManager struct {
	svc    *Service
	params passwordParams
	// dummy uses the real params so the work matches even with overrides.
	dummy func() string
}

func newPasswordManager(svc *Service, params passwordParams) *PasswordManager {
	if params == (passwordParams{}) {
		params = defaultPasswordParams()
	}
	m := &PasswordManager{svc: svc, params: params}
	m.dummy = sync.OnceValue(func() string {
		h, err := hashPassword(dummyPassword, m.params)
		if err != nil {
			// Only when crypto/rand fails. Logins still fail closed.
			return ""
		}
		return h
	})
	return m
}

func (m *PasswordManager) Login(ctx context.Context, email, pw string) (*db.User, *http.Cookie, error) {
	email = normalizeEmail(email)
	u, err := m.svc.sys.GetUserByEmail(ctx, email)
	if errors.Is(err, pgx.ErrNoRows) {
		m.burn(pw)
		m.svc.record(
			ctx,
			Event{Action: ActionLoginDenied, Method: MethodPassword, Email: email, Detail: "unknown email"},
		)
		return nil, nil, errInvalidCredentials
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
	m.svc.touchCredential(ctx, passwordCredentialID(u.ID))
	return u, cookie, nil
}

func (m *PasswordManager) CheckPassword(ctx context.Context, userID, pw string) error {
	denied := func(detail string) error {
		m.svc.record(ctx, Event{Action: ActionLoginDenied, Method: MethodPassword, UserID: userID, Detail: detail})
		return errInvalidCredentials
	}
	cred, err := m.svc.sys.GetCredential(ctx, &db.GetCredentialParams{UserID: userID, ID: passwordCredentialID(userID)})
	if errors.Is(err, pgx.ErrNoRows) {
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

func (m *PasswordManager) HasPassword(ctx context.Context, userID string) (bool, error) {
	_, err := m.svc.sys.GetCredential(ctx, &db.GetCredentialParams{UserID: userID, ID: passwordCredentialID(userID)})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// SetPassword revokes every session so a stolen one cannot outlive a reset.
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

func (m *PasswordManager) DeletePassword(ctx context.Context, userID string) error {
	return m.svc.sys.DeleteCredential(ctx, &db.DeleteCredentialParams{UserID: userID, ID: passwordCredentialID(userID)})
}

// Store does not revoke sessions, unlike SetPassword.
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

func (m *PasswordManager) burn(password string) {
	if h := m.dummy(); h != "" {
		_, _ = verifyPassword(password, h)
	}
}

// normalizeEmail matches the schema's email = lower(email) check.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// hashPassword encodes in PHC format: $argon2id$v=19$m=...,t=...,p=...$salt$hash.
func hashPassword(password string, p passwordParams) (string, error) {
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2Key(password, salt, p)
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

func verifyPassword(password, encoded string) (bool, error) {
	p, salt, key, err := decodeHash(encoded)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(key, argon2Key(password, salt, p)) == 1, nil
}

func needsRehash(encoded string, p passwordParams) bool {
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

func decodeHash(encoded string) (passwordParams, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return passwordParams{}, nil, nil, errors.New("iam: invalid hash format")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return passwordParams{}, nil, nil, errors.New("iam: incompatible argon2 version")
	}

	var p passwordParams
	if _, err := fmt.Sscanf(
		parts[3],
		"m=%d,t=%d,p=%d",
		&p.Memory,
		&p.Time,
		&p.Threads,
	); err != nil {
		return passwordParams{}, nil, nil, errors.New("iam: invalid parameters")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return passwordParams{}, nil, nil, errors.New("iam: invalid salt")
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return passwordParams{}, nil, nil, errors.New("iam: invalid hash")
	}

	p.SaltLen = uint32(len(salt)) // #nosec G115 -- decoded salt and key are small, bounded slices.
	p.KeyLen = uint32(len(key))   // #nosec G115 -- decoded salt and key are small, bounded slices.
	return p, salt, key, nil
}

func mapUserError(err error) error {
	if db.IsUniqueViolation(err) {
		return ErrEmailTaken
	}
	return err
}
