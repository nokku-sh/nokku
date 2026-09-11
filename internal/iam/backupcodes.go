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

// RotateBackupCodes replaces the user's existing backup codes with a fresh
// set and returns the plaintext codes, shown to the user exactly once.
// Delete and reinsert run in one transaction: a partial failure must never
// leave the user with zero backup codes and no way back in.
func (s *Service) RotateBackupCodes(ctx context.Context, userID string) ([]string, error) {
	fresh := make([]string, BackupCodeCount)
	for i := range fresh {
		raw := make([]byte, backupCodeBytes)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		fresh[i] = backupEncoding.EncodeToString(raw)
	}

	err := s.conn.WithTx(ctx, func(q *db.Queries) error {
		if err := deleteCredentialsOfType(ctx, q, userID, MethodBackupCode); err != nil {
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

// ListBackupCodes returns the user's remaining (unspent) backup codes.
func (s *Service) ListBackupCodes(ctx context.Context, userID string) ([]*db.Credential, error) {
	return s.q.ListCredentialsByType(ctx, &db.ListCredentialsByTypeParams{
		UserID: userID,
		Type:   string(MethodBackupCode),
	})
}

// DeleteBackupCodes removes every remaining backup code.
func (s *Service) DeleteBackupCodes(ctx context.Context, userID string) error {
	return deleteCredentialsOfType(ctx, s.q, userID, MethodBackupCode)
}

// LoginWithBackupCode verifies a single-use backup code and returns the
// user. Consumption is atomic: a code can never be spent twice.
func (s *Service) LoginWithBackupCode(ctx context.Context, email, code string) (*db.User, *http.Cookie, error) {
	email = normalizeEmail(email)
	code = normalizeBackupCode(code)
	u, err := s.q.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, ErrInvalidCredentials
		}
		return nil, nil, err
	}

	// Rejected logins must not burn a scarce recovery code, so the account
	// state is checked before the code is consumed.
	if !u.Active {
		return nil, nil, ErrInactive
	}
	if !u.EmailVerified {
		return nil, nil, ErrEmailUnverified
	}

	hash, err := crypto.HashToken(code)
	if err != nil {
		return nil, nil, err
	}
	if _, err := s.q.ConsumeCredentialBySubject(ctx, &db.ConsumeCredentialBySubjectParams{
		Type:    string(MethodBackupCode),
		Subject: hash.Hash(),
		UserID:  u.ID,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
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
		}
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
