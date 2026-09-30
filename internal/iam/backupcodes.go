package iam

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
)

const (
	backupCodeCount = 10
	backupCodeBytes = 10 // 80 bits
)

// backupEncoding skips ambiguous glyphs (0/O, 1/I/L) so printed codes retype cleanly.
var backupEncoding = base32.NewEncoding("ABCDEFGHJKLMNPQRSTUVWXYZ23456789").
	WithPadding(base32.NoPadding)

func (s *Service) RotateBackupCodes(ctx context.Context) ([]string, error) {
	fresh := make([]string, backupCodeCount)
	for i := range fresh {
		raw := make([]byte, backupCodeBytes)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		fresh[i] = backupEncoding.EncodeToString(raw)
	}

	userID := actor.UserIDFromContext(ctx)
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

func (s *Service) ListBackupCodes(ctx context.Context) ([]*db.Credential, error) {
	return s.ListCredentialsByType(ctx, MethodBackupCode)
}

func (s *Service) DeleteBackupCodes(ctx context.Context) error {
	return s.UnlinkIdentity(ctx, "", MethodBackupCode)
}

func (s *Service) LoginWithBackupCode(ctx context.Context, email, code string) (*db.User, *http.Cookie, error) {
	u, err := s.sys.GetUserByEmail(ctx, normalizeEmail(email))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, errInvalidCredentials
	}
	if err != nil {
		return nil, nil, err
	}
	// Check the account gates first so a refused login doesn't burn a code.
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
		return nil, nil, errInvalidCredentials
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
		return nil, nil, errInvalidCredentials
	} else if err != nil {
		return nil, nil, err
	}
	cookie, err := s.completeLogin(ctx, u, MethodBackupCode)
	if err != nil {
		return nil, nil, err
	}
	return u, cookie, nil
}

// normalizeBackupCode accepts codes pasted as XXXX-XXXX-XXXX-XXXX or lowercase.
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
