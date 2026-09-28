package email

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"time"

	"github.com/caarlos0/env/v11"

	"github.com/nokku-sh/nokku/internal/cache"

	"github.com/nokku-sh/nokku/web"
)

var ErrCooldown = errors.New("email cooldown active")

// Service only delivers when an SMTP host is set.
type Service struct {
	sender Sender
	cache  cache.Cache
	appURL string

	From     string        `env:"NOKKU_EMAIL_SENDER"   envDefault:"noreply@system.nokku.sh"`
	Cooldown time.Duration `env:"NOKKU_EMAIL_COOLDOWN" envDefault:"15m"`

	SMTPHost     string `env:"NOKKU_SMTP_HOST"`
	SMTPPort     int    `env:"NOKKU_SMTP_PORT"     envDefault:"587"`
	SMTPUsername string `env:"NOKKU_SMTP_USERNAME"`
	SMTPPassword string `env:"NOKKU_SMTP_PASSWORD"`
}

type sendRequest struct {
	userID   string
	to       string
	subject  string
	template string
	data     any
}

func New(appURL string, cache cache.Cache) (*Service, error) {
	svc, err := env.ParseAs[Service]()
	if err != nil {
		return nil, err
	}
	svc.appURL, svc.cache, svc.sender = appURL, cache, noopSender{}

	if svc.SMTPHost == "" {
		slog.Info("email delivery disabled, set NOKKU_SMTP_HOST to enable it")
		return &svc, nil
	}
	svc.sender, err = newSMTPSender(svc.SMTPHost, svc.SMTPPort, svc.SMTPUsername, svc.SMTPPassword)
	if err != nil {
		return nil, err
	}
	slog.Info("email delivery enabled", "host", svc.SMTPHost, "port", svc.SMTPPort)
	return &svc, nil
}

func (s *Service) SendWelcomeEmail(
	ctx context.Context,
	userID, email, username, verifyURL, expiry string,
) error {
	return s.sendTemplate(ctx, sendRequest{
		userID:   userID,
		to:       email,
		subject:  "Welcome to Nokku",
		template: "welcome",
		data: WelcomeTemplateData{
			UserName:        username,
			VerificationURL: verifyURL,
			Expiration:      expiry,
		},
	})
}

func (s *Service) SendVerificationEmail(
	ctx context.Context,
	userID, email, verifyURL, expiry string,
) error {
	return s.sendTemplate(ctx, sendRequest{
		userID:   userID,
		to:       email,
		subject:  "Verify your email address",
		template: "verification",
		data: VerificationTemplateData{
			VerificationURL: verifyURL,
			Expiration:      expiry,
		},
	})
}

func (s *Service) SendRecoveryEmail(
	ctx context.Context,
	userID, email, recoveryURL, expiry string,
) error {
	return s.sendTemplate(ctx, sendRequest{
		userID:   userID,
		to:       email,
		subject:  "Reset your password",
		template: "recovery",
		data: RecoveryTemplateData{
			RecoveryURL: recoveryURL,
			Expiration:  expiry,
		},
	})
}

func (s *Service) SendNewLoginEmail(
	ctx context.Context,
	userID, email, deviceID, deviceName, ip string,
) error {
	return s.sendTemplate(ctx, sendRequest{
		userID:   userID,
		to:       email,
		subject:  "New sign-in to your account",
		template: "new-login",
		data: NewLoginTemplateData{
			ProfileURL: s.appURL + "/profile/security",
			DeviceID:   deviceID,
			DeviceName: deviceName,
			IPAddress:  ip,
			EventTime:  time.Now().UTC().Format(time.RFC1123),
		},
	})
}

// sendTemplate claims the cooldown slot before sending and releases it on
// failure, so concurrent requests cannot double-send.
func (s *Service) sendTemplate(ctx context.Context, req sendRequest) error {
	if req.userID == "" {
		return errors.New("email user id is required")
	}
	html, err := render(req.template, req.data)
	if err != nil {
		return err
	}

	key := "email_cooldown:" + req.userID + ":" + req.template
	claimed, err := s.cache.SetNX(ctx, key, nil, s.Cooldown)
	if err != nil {
		return fmt.Errorf("email cooldown: %w", err)
	}
	if !claimed {
		return ErrCooldown
	}

	err = s.sender.Send(ctx, Message{
		From:    "Nokku <" + s.From + ">",
		To:      req.to,
		Subject: req.subject,
		HTML:    html,
	})
	if err != nil {
		_ = s.cache.Delete(context.WithoutCancel(ctx), key)
	}
	return err
}

func render(name string, data any) (string, error) {
	templatePath := fmt.Sprintf("email/out/%s.html", name)
	content, err := web.EmailFS.ReadFile(templatePath)
	if err != nil {
		return "", fmt.Errorf("template %s not found: %w", name, err)
	}

	tmpl, err := template.New(name).Option("missingkey=error").Parse(string(content))
	if err != nil {
		return "", fmt.Errorf("failed to parse template %s: %w", name, err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template %s: %w", name, err)
	}

	return buf.String(), nil
}
