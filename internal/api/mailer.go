package api

import (
	"context"
	"log/slog"

	"github.com/mizuchilabs/kagi"
	"github.com/mizuchilabs/kagi/server"

	"github.com/nokku-sh/nokku/internal/auth"
	"github.com/nokku-sh/nokku/internal/config"
)

// kagiMailer adapts nokku's email service to kagi's server.Mailer. The server
// mints the token and builds the link; this only delivers it.
type kagiMailer struct {
	cfg *config.Config
}

var _ server.Mailer = (*kagiMailer)(nil)

func (m kagiMailer) SendVerification(_ context.Context, u kagi.User, l server.Link) error {
	if err := m.cfg.Email.SendVerificationEmail(
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

func (m kagiMailer) SendWelcome(_ context.Context, u kagi.User, l server.Link) error {
	if err := m.cfg.Email.SendWelcomeEmail(
		context.Background(),
		u.ID,
		u.Email,
		auth.UsernameFromEmail(u.Email),
		l.URL,
		l.ExpiresIn.String(),
	); err != nil {
		slog.Error("failed to send welcome email", "error", err)
	}
	return nil
}

func (m kagiMailer) SendPasswordReset(_ context.Context, u kagi.User, l server.Link) error {
	if err := m.cfg.Email.SendRecoveryEmail(
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
