package email

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/textproto"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"

	"github.com/nokku-sh/nokku/internal/cache"

	"github.com/nokku-sh/nokku/web"
)

// ErrCooldown means the same kind of mail went to this person a moment ago.
var ErrCooldown = errors.New("email cooldown active")

const (
	// cooldownEntries bounds the cooldown store, one entry per user and template.
	cooldownEntries = 10_000
	emailConfirm    = "email-confirm"
	magicLink       = "magic-link"
)

// Service only delivers when an SMTP host is set.
type Service struct {
	sender sender
	cache  *cache.Memory
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

func New(ctx context.Context, appURL string) (*Service, error) {
	svc, err := env.ParseAs[Service]()
	if err != nil {
		return nil, err
	}
	svc.appURL, svc.cache, svc.sender = appURL, cache.NewMemory(cooldownEntries), noopSender{}

	if svc.SMTPHost == "" {
		slog.Warn("email delivery disabled, set NOKKU_SMTP_HOST to enable it")
		return &svc, nil
	}
	// A default sender would be somebody else's domain, and relays reject that.
	if svc.From == "" {
		return nil, errors.New("NOKKU_EMAIL_SENDER is required when NOKKU_SMTP_HOST is set")
	}
	relay, err := newSMTPSender(svc.SMTPHost, svc.SMTPPort, svc.SMTPUsername, svc.SMTPPassword)
	if err != nil {
		return nil, err
	}
	if err := relay.checkLogin(ctx); err != nil {
		// 535 is the relay saying no to the credentials, a setting that does
		// not fit. Anything else may be an outage, the server still starts.
		if e, ok := errors.AsType[*textproto.Error](err); ok && e.Code == 535 {
			return nil, fmt.Errorf(
				"%s rejected NOKKU_SMTP_USERNAME and NOKKU_SMTP_PASSWORD: %w", svc.SMTPHost, err,
			)
		}
		slog.Warn("smtp relay check failed, mail may not go out", "error", err)
	}
	svc.sender = relay
	return &svc, nil
}

// HasSMTP is whether mail can go out at all.
func (s *Service) HasSMTP() bool {
	return s.SMTPHost != ""
}

func (s *Service) SendMagicLinkEmail(ctx context.Context, userID, email, link, expiry string) error {
	return s.sendTemplate(ctx, sendRequest{
		userID:   userID,
		to:       email,
		subject:  "Your sign-in link",
		template: magicLink,
		data: linkTemplateData{
			Operator:   s.Operator,
			LinkURL:    link,
			Expiration: expiry,
		},
	})
}

// SendOwnerLinkEmail is the sign-in link for the owner of a workspace the
// hosted signup made. Every signup makes a new owner, so the cooldown is
// keyed by the address.
func (s *Service) SendOwnerLinkEmail(ctx context.Context, email, link, expiry string) error {
	return s.SendMagicLinkEmail(ctx, email, email, link, expiry)
}

// OwnerLinkOnCooldown is whether email got that link a moment ago. Asked
// before the next workspace is made, its mail would not go out.
func (s *Service) OwnerLinkOnCooldown(ctx context.Context, email string) bool {
	_, err := s.cache.Get(ctx, cooldownKey(email, magicLink))
	return err == nil
}

// SendEmailChangeConfirm goes to the new address, the account only switches
// to it once the link is used.
func (s *Service) SendEmailChangeConfirm(ctx context.Context, userID, email, link, expiry string) error {
	return s.sendTemplate(ctx, sendRequest{
		userID:   userID,
		to:       email,
		subject:  "Confirm your new email address",
		template: emailConfirm,
		data: linkTemplateData{
			Operator:   s.Operator,
			LinkURL:    link,
			Expiration: expiry,
		},
	})
}

// EmailChangeOnCooldown is whether userID asked for an email change a moment
// ago. Asked before a new change replaces the pending one.
func (s *Service) EmailChangeOnCooldown(ctx context.Context, userID string) bool {
	_, err := s.cache.Get(ctx, cooldownKey(userID, emailConfirm))
	return err == nil
}

// SendSignupLinkEmail goes to someone without an account yet, so the
// cooldown is keyed by the address.
func (s *Service) SendSignupLinkEmail(ctx context.Context, email, name, workspace, link, expiry string) error {
	return s.sendTemplate(ctx, sendRequest{
		userID:   email,
		to:       email,
		subject:  "Join " + workspace + " on Nokku",
		template: "signup-link",
		data: signupTemplateData{
			Operator:   s.Operator,
			UserName:   name,
			Workspace:  workspace,
			LinkURL:    link,
			Expiration: expiry,
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
		data: changeNoticeTemplateData{
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
		data: newLoginTemplateData{
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

	key := cooldownKey(req.userID, req.template)
	claimed, err := s.cache.SetNX(ctx, key, nil, s.Cooldown)
	// A full store must not hold back a reset or a sign-in alert. Every signup
	// adds an entry, so it can be filled from outside.
	if err != nil {
		slog.Warn("email cooldown not recorded, sending anyway", "error", err)
	} else if !claimed {
		return ErrCooldown
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

func cooldownKey(userID, template string) string {
	return "email_cooldown:" + userID + ":" + template
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
