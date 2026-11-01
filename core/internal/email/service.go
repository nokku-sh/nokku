package email

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"log/slog"
	"math"
	"net/textproto"
	"strings"
	texttemplate "text/template"
	"time"
	"unicode/utf8"

	"github.com/caarlos0/env/v11"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/cache"
)

const (
	cooldown        = 15 * time.Minute
	cooldownEntries = 10_000
	emailConfirm    = "email-confirm"
	mailDate        = "2 Jan 2006"
	mailTime        = "2 Jan 2006, 15:04 UTC"
	magicLink       = "magic-link"
)

const sendTimeout = 10 * time.Second

// Built with react-email in the email repo, an .html and a .txt per mail.
//
//go:embed templates
var templates embed.FS

var ErrCooldown = errors.New("email cooldown active")

// relayCheckTimeout is a var so tests can shorten it.
var relayCheckTimeout = 3 * time.Second

var templateFuncs = map[string]any{"year": func() int { return time.Now().Year() }}

// A broken template fails the tests and the start, never a send.
var (
	htmlTemplates = htmltemplate.Must(htmltemplate.New("").Funcs(templateFuncs).Option("missingkey=error").
			ParseFS(templates, "templates/*.html"))
	textTemplates = texttemplate.Must(texttemplate.New("").Funcs(templateFuncs).Option("missingkey=error").
			ParseFS(templates, "templates/*.txt"))
)

type Service struct {
	sender sender
	cache  *cache.TTL[string, struct{}]
	appURL string

	From string `env:"NOKKU_EMAIL_SENDER"`

	SMTPHost     string `env:"NOKKU_SMTP_HOST"`
	SMTPPort     int    `env:"NOKKU_SMTP_PORT"     envDefault:"587"`
	SMTPUsername string `env:"NOKKU_SMTP_USERNAME"`
	SMTPPassword string `env:"NOKKU_SMTP_PASSWORD"`

	Operator Operator
}

// Operator is empty by default, so self-host never shows the Nokku company.
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
	userID string
	// ref gives mails about one thing their own cooldown.
	ref      string
	to       string
	subject  string
	template string
	data     any
}

type TrialEnding struct {
	UserID, Email         string
	Workspace, BillingURL string
	Next                  int32 // next reminder, days before the end or 0
	Ends, Deleted         time.Time
}

type DeletionWarning struct {
	UserID, Email   string
	Workspace, Slug string
	BillingURL      string
	Trial           bool
	Next            int32 // next warning, days before the deletion or 0
	Ended, Deleted  time.Time
}

type AccessRequest struct {
	UserID, Email              string
	RequesterID, RequestID     string
	Requester, Target, Account string
	Reason, URL                string
	Duration                   time.Duration
}

// AccessDecision has Until set when the request was approved.
type AccessDecision struct {
	UserID, Email                       string
	RequestID, Decider, Target, Account string
	URL                                 string
	Until                               *time.Time
}

type body struct {
	text string
	html string
}

func New(ctx context.Context, appURL string) (*Service, error) {
	svc, err := env.ParseAs[Service]()
	if err != nil {
		return nil, err
	}
	svc.appURL, svc.cache, svc.sender = appURL, cache.New[string, struct{}](cooldownEntries, cooldown), noopSender{}

	if svc.SMTPHost == "" {
		slog.Warn("email delivery disabled, set NOKKU_SMTP_HOST to enable it")
		return &svc, nil
	}
	// A default sender would be somebody else's domain, and relays reject that.
	if svc.From == "" {
		return nil, errors.New("NOKKU_EMAIL_SENDER is required when NOKKU_SMTP_HOST is set")
	}
	relay, err := newSMTPSender(svc.SMTPHost, svc.SMTPPort, svc.SMTPUsername, svc.SMTPPassword, sendTimeout)
	if err != nil {
		return nil, err
	}
	// Own client with a short timeout, go-mail only honors ctx while dialing.
	probe, err := newSMTPSender(svc.SMTPHost, svc.SMTPPort, svc.SMTPUsername, svc.SMTPPassword, relayCheckTimeout)
	if err != nil {
		return nil, err
	}
	if err := probe.checkLogin(ctx); err != nil {
		// 535 is bad credentials. Anything else may be an outage, so boot on.
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

// SendOwnerLinkEmail keys the cooldown by address, each signup is a new owner.
func (s *Service) SendOwnerLinkEmail(ctx context.Context, email, link string, expiry time.Duration) error {
	return s.SendMagicLinkEmail(ctx, email, email, link, expiry)
}

// OwnerLinkOnCooldown is asked first, or a new workspace would get no mail.
func (s *Service) OwnerLinkOnCooldown(email string) bool {
	_, on := s.cache.Get(cooldownKey(email, magicLink))
	return on
}

// SendEmailChangeConfirm goes to the new address, the link makes the switch.
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
func (s *Service) EmailChangeOnCooldown(userID string) bool {
	_, on := s.cache.Get(cooldownKey(userID, emailConfirm))
	return on
}

// SendInviteEmail cools down per address and workspace, tenants don't share it.
func (s *Service) SendInviteEmail(
	ctx context.Context,
	email, workspace, role, link string,
	expiry time.Duration,
) error {
	return s.sendTemplate(ctx, sendRequest{
		userID:   email,
		ref:      actor.WorkspaceIDFromContext(ctx),
		to:       email,
		subject:  "Join " + workspace + " on Nokku",
		template: "invite",
		data: inviteTemplateData{
			Operator:   s.Operator,
			Workspace:  workspace,
			Role:       role,
			LinkURL:    link,
			Expiration: lifetime(expiry),
		},
	})
}

// SendEmailChangeNotice masks the new address, the reader may not have asked.
func (s *Service) SendEmailChangeNotice(
	ctx context.Context,
	userID, email, newEmail, cancelURL string,
	expiry time.Duration,
) error {
	local, domain, _ := strings.Cut(newEmail, "@")
	_, first := utf8.DecodeRuneInString(local)
	return s.sendTemplate(ctx, sendRequest{
		userID:   userID,
		to:       email,
		subject:  "Your email address is being changed",
		template: "email-change",
		data: changeNoticeTemplateData{
			Operator:   s.Operator,
			NewEmail:   local[:first] + "***@" + domain,
			CancelURL:  cancelURL,
			Expiration: lifetime(expiry),
		},
	})
}

// SendNewLoginEmail cools down per device, so a second device gets its own.
func (s *Service) SendNewLoginEmail(
	ctx context.Context,
	userID, email, deviceID, deviceName, ip string,
) error {
	return s.sendTemplate(ctx, sendRequest{
		userID:   userID,
		to:       email,
		subject:  "New sign-in from " + deviceName,
		template: "new-login",
		ref:      deviceID,
		data: newLoginTemplateData{
			Operator:   s.Operator,
			ProfileURL: s.appURL + "/profile/security",
			DeviceID:   deviceID,
			DeviceName: deviceName,
			IPAddress:  ip,
			EventTime:  time.Now().UTC().Format(mailTime),
		},
	})
}

// SendNewWayInEmail cools down per credential, so each new one gets a mail.
func (s *Service) SendNewWayInEmail(ctx context.Context, userID, email, credentialID, what, ip string) error {
	return s.sendTemplate(ctx, sendRequest{
		userID:   userID,
		to:       email,
		subject:  "New way to sign in to your account",
		template: "new-way-in",
		ref:      credentialID,
		data: newWayInTemplateData{
			Operator:   s.Operator,
			ProfileURL: s.appURL + "/profile/security",
			What:       what,
			IPAddress:  ip,
			EventTime:  time.Now().UTC().Format(mailTime),
		},
	})
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

// SendAccessRequestEmail cools down per requester, so repeats flood nobody.
func (s *Service) SendAccessRequestEmail(ctx context.Context, r AccessRequest) error {
	return s.sendTemplate(ctx, sendRequest{
		userID:   r.UserID,
		ref:      r.RequesterID,
		to:       r.Email,
		subject:  r.Requester + " asks for " + r.Account + " on " + r.Target,
		template: "access-request",
		data: accessRequestTemplateData{
			Operator:   s.Operator,
			Requester:  r.Requester,
			Target:     r.Target,
			Account:    r.Account,
			Duration:   lifetime(r.Duration),
			Reason:     r.Reason,
			RequestURL: r.URL,
			RequestID:  r.RequestID,
		},
	})
}

func (s *Service) SendAccessDecisionEmail(ctx context.Context, d AccessDecision) error {
	decision, until := "denied", ""
	if d.Until != nil {
		decision, until = "approved", d.Until.UTC().Format(mailTime)
	}
	return s.sendTemplate(ctx, sendRequest{
		userID:   d.UserID,
		ref:      d.RequestID,
		to:       d.Email,
		subject:  "Your request for " + d.Account + " on " + d.Target + " was " + decision,
		template: "access-request-decided",
		data: accessDecisionTemplateData{
			Operator:   s.Operator,
			Decision:   decision,
			Decider:    d.Decider,
			Target:     d.Target,
			Account:    d.Account,
			Until:      until,
			RequestURL: d.URL,
			RequestID:  d.RequestID,
		},
	})
}

// sendTemplate claims the cooldown before sending, so nothing double-sends.
func (s *Service) sendTemplate(ctx context.Context, req sendRequest) error {
	if req.userID == "" {
		return errors.New("email user id is required")
	}
	body, err := render(req.template, req.data)
	if err != nil {
		return err
	}

	key := cooldownKey(req.userID, req.template+req.ref)
	// A full store evicts the oldest, so a signup flood can't block an alert.
	if !s.cache.SetNX(key, struct{}{}) {
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
		s.cache.Delete(key)
	}
	return err
}

func cooldownKey(userID, template string) string {
	return "email_cooldown:" + userID + ":" + template
}

// render uses text/template for the text part, html escaping breaks its URLs.
func render(name string, data any) (body, error) {
	var html, text bytes.Buffer
	if err := htmlTemplates.ExecuteTemplate(&html, name+".html", data); err != nil {
		return body{}, fmt.Errorf("render %s.html: %w", name, err)
	}
	if err := textTemplates.ExecuteTemplate(&text, name+".txt", data); err != nil {
		return body{}, fmt.Errorf("render %s.txt: %w", name, err)
	}
	return body{text: text.String(), html: html.String()}, nil
}

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
