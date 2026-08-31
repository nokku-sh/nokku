package auth

import (
	"context"
	"log/slog"
	"strings"

	"github.com/mizuchilabs/kagi"

	"github.com/nokku-sh/nokku/internal/email"
)

// kagiMailer adapts nokku's email service to kagi's Mailer. kagi mints the
// token and builds the link; this only delivers it.
type kagiMailer struct {
	email *email.Service
}

var _ kagi.Mailer = (*kagiMailer)(nil)

func (m kagiMailer) SendWelcome(_ context.Context, u kagi.User, l kagi.Link) error {
	// Fall back to the email local part when no display name is set.
	name := u.DisplayName
	if name == "" {
		name, _, _ = strings.Cut(u.Email, "@")
	}
	if err := m.email.SendWelcomeEmail(
		context.Background(),
		u.ID,
		u.Email,
		name,
		l.URL,
		l.ExpiresIn.String(),
	); err != nil {
		slog.Error("failed to send welcome email", "error", err)
	}
	return nil
}

func (m kagiMailer) SendVerification(_ context.Context, u kagi.User, l kagi.Link) error {
	if err := m.email.SendVerificationEmail(
		context.Background(),
		u.ID,
		u.Email,
		l.URL,
		l.ExpiresIn.String(),
	); err != nil {
		slog.Error("failed to send verification email", "error", err)
	}
	return nil
}

func (m kagiMailer) SendPasswordReset(_ context.Context, u kagi.User, l kagi.Link) error {
	if err := m.email.SendRecoveryEmail(
		context.Background(),
		u.ID,
		u.Email,
		l.URL,
		l.ExpiresIn.String(),
	); err != nil {
		slog.Error("failed to send recovery email", "error", err)
	}
	return nil
}
