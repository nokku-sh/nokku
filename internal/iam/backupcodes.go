package iam

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
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
func (s *Service) RotateBackupCodes(ctx context.Context, userID string) ([]string, error) {
	if err := s.DeleteBackupCodes(ctx, userID); err != nil {
		return nil, err
	}

	codes := make([]string, BackupCodeCount)
	for i := range codes {
		raw := make([]byte, backupCodeBytes)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		codes[i] = backupEncoding.EncodeToString(raw)
	}

	for _, code := range codes {
		hash, err := crypto.HashToken(code)
		if err != nil {
			return nil, err
		}
		if _, err := s.q.UpsertCredential(ctx, &db.UpsertCredentialParams{
			ID:      userID + ":backup:" + hash.Hash(),
			UserID:  userID,
			Type:    string(MethodBackupCode),
			Subject: hash.Hash(),
			Data:    []byte{},
		}); err != nil {
			return nil, err
		}
	}
	return codes, nil
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
	creds, err := s.ListBackupCodes(ctx, userID)
	if err != nil {
		return err
	}
	for _, c := range creds {
		if err := s.q.DeleteCredential(
			ctx,
			&db.DeleteCredentialParams{UserID: userID, ID: c.ID},
		); err != nil {
			return err
		}
	}
	return nil
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

// LoginWithBackupCode verifies a single-use backup code and returns the
// user. Consumption is atomic: a code can never be spent twice.
func (s *Service) LoginWithBackupCode(ctx context.Context, email, code string) (*db.User, error) {
	email = normalizeEmail(email)
	code = normalizeBackupCode(code)
	u, err := s.q.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	hash, err := crypto.HashToken(code)
	if err != nil {
		return nil, err
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
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}
	if !u.Active {
		return nil, ErrInactive
	}
	s.record(
		ctx,
		Event{
			Action: ActionLoginSucceeded,
			Kind:   KindUser,
			Method: MethodBackupCode,
			UserID: u.ID,
			Email:  u.Email,
		},
	)
	return u, nil
}
