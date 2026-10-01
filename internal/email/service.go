package email

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"

	"github.com/nokku-sh/nokku/internal/cache"

	"github.com/nokku-sh/nokku/web"
)

var errCooldown = errors.New("email cooldown active")

// Service only delivers when an SMTP host is set.
type Service struct {
	sender sender
	cache  cache.Cache
	appURL string

	From     string        `env:"NOKKU_EMAIL_SENDER"`
	Cooldown time.Duration `env:"NOKKU_EMAIL_COOLDOWN" envDefault:"15m"`

	SMTPHost     string `env:"NOKKU_SMTP_HOST"`
	SMTPPort     int    `env:"NOKKU_SMTP_PORT"     envDefault:"587"`
	SMTPUsername string `env:"NOKKU_SMTP_USERNAME"`
	SMTPPassword string `env:"NOKKU_SMTP_PASSWORD"`

	Operator Operator
}

// Operator is whoever runs this server. Empty by default, so a self-hosted
// server never shows the Nokku company in its mails or legal links.
type Operator struct {
	Name         string `env:"NOKKU_OPERATOR_NAME"`
	Address      string `env:"NOKKU_OPERATOR_ADDRESS"`
	SupportEmail string `env:"NOKKU_OPERATOR_SUPPORT_EMAIL"`
	WebsiteURL   string `env:"NOKKU_OPERATOR_WEBSITE_URL"`
	TermsURL     string `env:"NOKKU_OPERATOR_TERMS_URL"`
	PrivacyURL   string `env:"NOKKU_OPERATOR_PRIVACY_URL"`
	ImprintURL   string `env:"NOKKU_OPERATOR_IMPRINT_URL"`
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
	// A default sender would be somebody else's domain, and relays reject that.
	if svc.From == "" {
		return nil, errors.New("NOKKU_EMAIL_SENDER is required when NOKKU_SMTP_HOST is set")
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
			Operator:        s.Operator,
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
			Operator:        s.Operator,
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
			Operator:    s.Operator,
			RecoveryURL: recoveryURL,
			Expiration:  expiry,
		},
	})
}

// SendEmailChangeNotice goes to the current address and only shows the new
// one masked, the reader may not be the one who asked.
func (s *Service) SendEmailChangeNotice(
	ctx context.Context,
	userID, email, newEmail, cancelURL, expiry string,
) error {
	local, domain, _ := strings.Cut(newEmail, "@")
	return s.sendTemplate(ctx, sendRequest{
		userID:   userID,
		to:       email,
		subject:  "Your email address is being changed",
		template: "email-change",
		data: ChangeNoticeTemplateData{
			Operator:   s.Operator,
			NewEmail:   local[:min(1, len(local))] + "***@" + domain,
			CancelURL:  cancelURL,
			Expiration: expiry,
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
			Operator:   s.Operator,
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
		return errCooldown
	}

	err = s.sender.Send(ctx, message{
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
