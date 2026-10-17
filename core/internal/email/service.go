package email

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"io"
	"log/slog"
	"math"
	"net/textproto"
	"strings"
	texttemplate "text/template"
	"time"

	"github.com/caarlos0/env/v11"

	"github.com/nokku-sh/nokku/core/internal/cache"
)

// The templates are edited by hand, an .html and a .txt per mail.
//
//go:embed templates
var templates embed.FS

// ErrCooldown means the same kind of mail went to this person a moment ago.
var ErrCooldown = errors.New("email cooldown active")

const (
	// cooldown is the wait between two mails of the same kind to one person.
	cooldown = 15 * time.Minute
	// cooldownEntries bounds the cooldown store, one entry per user and template.
	cooldownEntries = 10_000
	emailConfirm    = "email-confirm"
	// mailDate is how a mail names a day.
	mailDate  = "2 Jan 2006"
	magicLink = "magic-link"
)

// Service only delivers when an SMTP host is set.
type Service struct {
	sender sender
	cache  *cache.Memory
	appURL string

	From string `env:"NOKKU_EMAIL_SENDER"`

	SMTPHost     string `env:"NOKKU_SMTP_HOST"`
	SMTPPort     int    `env:"NOKKU_SMTP_PORT"     envDefault:"587"`
	SMTPUsername string `env:"NOKKU_SMTP_USERNAME"`
	SMTPPassword string `env:"NOKKU_SMTP_PASSWORD"`

	Operator Operator
}

// Operator is empty by default, so a self-hosted server never shows the Nokku company in its mails.
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
		// 535 is the relay refusing the credentials. Anything else may be an outage, the server still starts.
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

func (s *Service) HasSMTP() bool {
	return s.SMTPHost != ""
}

func (s *Service) SendMagicLinkEmail(
	ctx context.Context,
	userID, email, link string,
	expiry time.Duration,
) error {
	return s.sendTemplate(ctx, sendRequest{
		userID:   userID,
		to:       email,
		subject:  "Your sign-in link",
		template: magicLink,
		data: linkTemplateData{
			Operator:   s.Operator,
			LinkURL:    link,
			Expiration: lifetime(expiry),
		},
	})
}

// SendOwnerLinkEmail keys the cooldown by the address, every hosted signup makes a new owner.
func (s *Service) SendOwnerLinkEmail(ctx context.Context, email, link string, expiry time.Duration) error {
	return s.SendMagicLinkEmail(ctx, email, email, link, expiry)
}

// OwnerLinkOnCooldown is asked before the next workspace is made, its mail would not go out.
func (s *Service) OwnerLinkOnCooldown(ctx context.Context, email string) bool {
	_, err := s.cache.Get(ctx, cooldownKey(email, magicLink))
	return err == nil
}

// SendEmailChangeConfirm goes to the new address, the account only switches once the link is used.
func (s *Service) SendEmailChangeConfirm(
	ctx context.Context,
	userID, email, link string,
	expiry time.Duration,
) error {
	return s.sendTemplate(ctx, sendRequest{
		userID:   userID,
		to:       email,
		subject:  "Confirm your new email address",
		template: emailConfirm,
		data: linkTemplateData{
			Operator:   s.Operator,
			LinkURL:    link,
			Expiration: lifetime(expiry),
		},
	})
}

// EmailChangeOnCooldown is asked before a new change replaces the pending one.
func (s *Service) EmailChangeOnCooldown(ctx context.Context, userID string) bool {
	_, err := s.cache.Get(ctx, cooldownKey(userID, emailConfirm))
	return err == nil
}

// SendSignupLinkEmail goes to someone without an account yet, so the cooldown is keyed by the address.
func (s *Service) SendSignupLinkEmail(
	ctx context.Context,
	email, name, workspace, link string,
	expiry time.Duration,
) error {
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
			Expiration: lifetime(expiry),
		},
	})
}

// SendEmailChangeNotice only shows the new address masked, the reader may not be the one who asked.
func (s *Service) SendEmailChangeNotice(
	ctx context.Context,
	userID, email, newEmail, cancelURL string,
	expiry time.Duration,
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
			Expiration: lifetime(expiry),
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
		subject:  "New sign-in from " + deviceName,
		template: "new-login",
		data: newLoginTemplateData{
			Operator:   s.Operator,
			ProfileURL: s.appURL + "/profile/security",
			DeviceID:   deviceID,
			DeviceName: deviceName,
			IPAddress:  ip,
			EventTime:  time.Now().UTC().Format("2 Jan 2006, 15:04 UTC"),
		},
	})
}

// TrialEnding is a mail to the owner of a hosted workspace whose trial runs out.
type TrialEnding struct {
	UserID, Email         string
	Workspace, BillingURL string
	Next                  int32 // days before the end of the next reminder, 0 for none
	Ends, Deleted         time.Time
}

func (s *Service) SendTrialEndingEmail(ctx context.Context, t TrialEnding) error {
	left := inDays(max(int(math.Ceil(time.Until(t.Ends).Hours()/24)), 1))
	return s.sendTemplate(ctx, sendRequest{
		userID:   t.UserID,
		to:       t.Email,
		subject:  "Your Nokku trial ends in " + left,
		template: "trial-ending",
		data: trialTemplateData{
			Operator:   s.Operator,
			Workspace:  t.Workspace,
			Left:       left,
			EndDate:    t.Ends.UTC().Format(mailDate),
			DeleteDate: t.Deleted.UTC().Format(mailDate),
			BillingURL: t.BillingURL,
			Next:       inDays(int(t.Next)),
		},
	})
}

// DeletionWarning is a mail to the owner of a hosted workspace that stopped paying and is about to be deleted.
type DeletionWarning struct {
	UserID, Email   string
	Workspace, Slug string
	BillingURL      string
	Trial           bool  // the workspace never paid, its trial ended
	Next            int32 // days before the deletion of the next warning, 0 for none
	Ended, Deleted  time.Time
}

func (s *Service) SendDeletionWarningEmail(ctx context.Context, w DeletionWarning) error {
	return s.sendTemplate(ctx, sendRequest{
		userID:   w.UserID,
		to:       w.Email,
		subject:  w.Workspace + " is deleted on " + w.Deleted.UTC().Format(mailDate),
		template: "workspace-deletion",
		data: deletionTemplateData{
			Operator:   s.Operator,
			Workspace:  w.Workspace,
			Slug:       w.Slug,
			Trial:      w.Trial,
			EndDate:    w.Ended.UTC().Format(mailDate),
			DeleteDate: w.Deleted.UTC().Format(mailDate),
			BillingURL: w.BillingURL,
			Next:       inDays(int(w.Next)),
		},
	})
}

// sendTemplate claims the cooldown slot before sending and releases it on failure, so nothing double-sends.
func (s *Service) sendTemplate(ctx context.Context, req sendRequest) error {
	if req.userID == "" {
		return errors.New("email user id is required")
	}
	body, err := render(req.template, req.data)
	if err != nil {
		return err
	}

	key := cooldownKey(req.userID, req.template)
	claimed, err := s.cache.SetNX(ctx, key, nil, cooldown)
	// A full store must not hold back a reset or an alert, signups can fill it from outside.
	if err != nil {
		slog.Warn("email cooldown not recorded, sending anyway", "error", err)
	} else if !claimed {
		return ErrCooldown
	}

	err = s.sender.Send(ctx, message{
		From:    "Nokku <" + s.From + ">",
		To:      req.to,
		Subject: req.subject,
		Text:    body.text,
		HTML:    body.html,
	})
	if err != nil {
		_ = s.cache.Delete(context.WithoutCancel(ctx), key)
	}
	return err
}

func cooldownKey(userID, template string) string {
	return "email_cooldown:" + userID + ":" + template
}

// A year typed into the footer would be wrong every January.
var templateFuncs = map[string]any{"year": func() int { return time.Now().Year() }}

type body struct {
	text string
	html string
}

// render fills both parts of a template. The text part goes through text/template, html escaping would break its URLs.
func render(name string, data any) (body, error) {
	html, err := renderFile("templates/"+name+".html", data, func(src string) (executor, error) {
		return htmltemplate.New(name).Funcs(templateFuncs).Option("missingkey=error").Parse(src)
	})
	if err != nil {
		return body{}, err
	}
	text, err := renderFile("templates/"+name+".txt", data, func(src string) (executor, error) {
		return texttemplate.New(name).Funcs(templateFuncs).Option("missingkey=error").Parse(src)
	})
	if err != nil {
		return body{}, err
	}
	return body{text: text, html: html}, nil
}

type executor interface {
	Execute(w io.Writer, data any) error
}

func renderFile(path string, data any, parse func(string) (executor, error)) (string, error) {
	content, err := templates.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("template %s not found: %w", path, err)
	}
	tmpl, err := parse(string(content))
	if err != nil {
		return "", fmt.Errorf("failed to parse template %s: %w", path, err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template %s: %w", path, err)
	}
	return buf.String(), nil
}

// lifetime words how long a link works in its largest whole unit, "24 hours" and not "24h0m0s".
// inDays words a count of days, empty for 0.
func inDays(n int) string {
	switch n {
	case 0:
		return ""
	case 1:
		return "1 day"
	}
	return fmt.Sprintf("%d days", n)
}

func lifetime(d time.Duration) string {
	n, unit := int(d/time.Minute), "minute"
	switch {
	case d >= 48*time.Hour && d%(24*time.Hour) == 0:
		n, unit = int(d/(24*time.Hour)), "day"
	case d >= time.Hour && d%time.Hour == 0:
		n, unit = int(d/time.Hour), "hour"
	}
	if n != 1 {
		unit += "s"
	}
	return fmt.Sprintf("%d %s", n, unit)
}
