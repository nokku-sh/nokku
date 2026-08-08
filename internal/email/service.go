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

type Service struct {
	sender Sender
	cache  cache.Cache

	appURL   string
	Driver   string        `env:"NOKKU_EMAIL_DRIVER"   envDefault:"noop"`
	Sender   string        `env:"NOKKU_EMAIL_SENDER"   envDefault:"noreply@system.nokku.sh"`
	Timeout  time.Duration `env:"NOKKU_EMAIL_TIMEOUT"  envDefault:"10s"`
	Cooldown time.Duration `env:"NOKKU_EMAIL_COOLDOWN" envDefault:"15m"`

	SMTPPort     int    `env:"NOKKU_SMTP_PORT"     envDefault:"587"`
	SMTPHost     string `env:"NOKKU_SMTP_HOST"`
	SMTPUsername string `env:"NOKKU_SMTP_USERNAME"`
	SMTPPassword string `env:"NOKKU_SMTP_PASSWORD"`
}

type sendRequest struct {
	userID   string
	to       Address
	subject  string
	template string
	data     any
}

func New(appURL string, cache cache.Cache) (*Service, error) {
	svc, err := env.ParseAs[Service]()
	if err != nil {
		return nil, err
	}
	if appURL == "" {
		return nil, errors.New("email app url is required")
	}

	svc.appURL = appURL
	svc.cache = cache

	sender, err := svc.buildSender()
	if err != nil {
		return nil, err
	}
	svc.sender = sender

	if svc.Sender == "" {
		return nil, errors.New("email sender address is required")
	}

	return &svc, nil
}

func (s *Service) buildSender() (Sender, error) {
	switch s.Driver {
	case "smtp":
		sender, err := newSMTPSender(smtpConfig{
			Host:     s.SMTPHost,
			Port:     s.SMTPPort,
			Username: s.SMTPUsername,
			Password: s.SMTPPassword,
			Timeout:  s.Timeout,
		})
		if err != nil {
			return nil, err
		}
		slog.Info("email delivery configured", "driver", "smtp")
		return sender, nil

	case "scaleway":
		sender, err := newScalewaySender()
		if err != nil {
			return nil, err
		}
		slog.Info("email delivery configured", "driver", "scaleway")
		return sender, nil

	default:
		slog.Info("email delivery disabled")
		return NoopSender{}, nil
	}
}

func (s *Service) SendWelcomeEmail(
	ctx context.Context,
	userID, email, username, verifyURL, expiry string,
) error {
	return s.sendTemplate(ctx, sendRequest{
		userID:   userID,
		to:       Address{Email: email},
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
		to:       Address{Email: email},
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
		to:       Address{Email: email},
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
	userID, email, deviceID, deviceName, location string,
) error {
	return s.sendTemplate(ctx, sendRequest{
		userID:   userID,
		to:       Address{Email: email},
		subject:  "New sign-in to your account",
		template: "new-login",
		data: NewLoginTemplateData{
			ProfileURL: s.appURL + "/profile/security",
			DeviceID:   deviceID,
			DeviceName: deviceName,
			Location:   location,
			EventTime:  time.Now().UTC().Format(time.RFC1123),
		},
	})
}

func (s *Service) sendTemplate(ctx context.Context, req sendRequest) error {
	if s == nil || s.sender == nil {
		slog.Warn("email service not initialized")
		return nil
	}

	if req.userID == "" {
		return fmt.Errorf("email user id is required")
	}

	cacheKey := "email_cooldown:" + req.userID + ":" + req.template
	if _, err := s.cache.Get(ctx, cacheKey); err == nil {
		slog.Debug("email cooldown active", "template", req.template)
		return ErrCooldown
	}

	htmlBody, err := render(req.template, req.data)
	if err != nil {
		return fmt.Errorf("failed to render %s email: %w", req.template, err)
	}

	msg := Message{
		From:     Address{Name: "Nokku", Email: s.Sender},
		To:       []Address{req.to},
		Subject:  req.subject,
		HTMLBody: htmlBody,
		Tags:     map[string]string{"template": req.template},
		Headers:  map[string]string{"X-Nokku-Template": req.template},
	}

	if err := s.sender.Send(ctx, msg); err != nil {
		return err
	}

	if err := s.cache.Set(ctx, cacheKey, nil, s.Cooldown); err != nil {
		slog.Warn("failed to set email cooldown", "error", err)
	}

	return nil
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
