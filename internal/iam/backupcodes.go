package iam

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
)

const (
	// BackupCodeCount is the number of codes issued per generation.
	BackupCodeCount = 10
	// backupCodeBytes is the entropy per code: 80 bits.
	backupCodeBytes = 10
)

// backupEncoding is base32 with a charset that avoids visually ambiguous
// glyphs (0/O, 1/I/L) so codes survive being read from a printout and
// retyped.
var backupEncoding = base32.NewEncoding("ABCDEFGHJKLMNPQRSTUVWXYZ23456789").
	WithPadding(base32.NoPadding)

// RotateBackupCodes replaces the request user's backup codes with a fresh
// set and returns the plaintext codes, shown exactly once. Delete and insert
// share one transaction, so a failure never leaves the user with no codes.
func (s *Service) RotateBackupCodes(ctx context.Context) ([]string, error) {
	fresh := make([]string, BackupCodeCount)
	for i := range fresh {
		raw := make([]byte, backupCodeBytes)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		fresh[i] = backupEncoding.EncodeToString(raw)
	}

	userID := UserIDFromContext(ctx)
	err := s.asSelf(ctx, func(q *db.Queries) error {
		if _, err := q.DeleteUserCredentialsByProvider(ctx, &db.DeleteUserCredentialsByProviderParams{
			UserID: userID,
			Type:   string(MethodBackupCode),
		}); err != nil {
			return err
		}
		for _, code := range fresh {
			hash, err := crypto.HashToken(code)
			if err != nil {
				return err
			}
			if _, err := q.UpsertCredential(ctx, &db.UpsertCredentialParams{
				ID:      userID + ":backup:" + hash.Hash(),
				UserID:  userID,
				Type:    string(MethodBackupCode),
				Subject: hash.Hash(),
				Data:    []byte{},
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return fresh, nil
}

// ListBackupCodes returns the request user's unspent backup codes.
func (s *Service) ListBackupCodes(ctx context.Context) ([]*db.Credential, error) {
	return s.ListCredentialsByType(ctx, MethodBackupCode)
}

// DeleteBackupCodes removes the request user's backup codes.
func (s *Service) DeleteBackupCodes(ctx context.Context) error {
	return s.UnlinkIdentity(ctx, "", MethodBackupCode)
}

// LoginWithBackupCode verifies a single-use backup code and signs the user
// in. Consumption is atomic, so a code is never spent twice.
func (s *Service) LoginWithBackupCode(ctx context.Context, email, code string) (*db.User, *http.Cookie, error) {
	u, err := s.sys.GetUserByEmail(ctx, normalizeEmail(email))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, nil, err
	}
	// A login the account gates refuse must not burn a scarce recovery
	// code, so they run before the code is consumed. completeLogin checks
	// them again.
	switch {
	case !u.Active:
		return nil, nil, ErrInactive
	case !u.EmailVerified:
		return nil, nil, ErrEmailUnverified
	}
	if err := s.enforceSSO(ctx, u.Email); err != nil {
		return nil, nil, err
	}

	hash, err := crypto.HashToken(normalizeBackupCode(code))
	if err != nil {
		return nil, nil, ErrInvalidCredentials
	}
	if _, err := s.sys.ConsumeCredentialBySubject(ctx, &db.ConsumeCredentialBySubjectParams{
		Type:    string(MethodBackupCode),
		Subject: hash.Hash(),
		UserID:  u.ID,
	}); errors.Is(err, pgx.ErrNoRows) {
		s.record(
			ctx,
			Event{
				Action: ActionLoginDenied,
				Method: MethodBackupCode,
				UserID: u.ID,
				Email:  u.Email,
				Detail: "unknown code",
			},
		)
		return nil, nil, ErrInvalidCredentials
	} else if err != nil {
		return nil, nil, err
	}
	cookie, err := s.completeLogin(ctx, u, MethodBackupCode)
	if err != nil {
		return nil, nil, err
	}
	return u, cookie, nil
}

// normalizeBackupCode uppercases and strips separators, so a code retyped
// from a printout or pasted as XXXX-XXXX-XXXX-XXXX still verifies against
// the hash stored at generation time (which is of the bare 16 characters).
func normalizeBackupCode(code string) string {
	var b strings.Builder
	b.Grow(len(code))
	for _, r := range code {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - 32)
		case (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		}
	}
	return b.String()
}
