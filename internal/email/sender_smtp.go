package email

import (
	"context"
	"fmt"
	"time"

	mail "github.com/wneessen/go-mail"
)

type smtpConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	Timeout  time.Duration
}

type smtpSender struct {
	client *mail.Client
}

func newSMTPSender(cfg smtpConfig) (*smtpSender, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("smtp host is required")
	}
	if cfg.Port == 0 {
		cfg.Port = 587
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}

	opts := []mail.Option{
		mail.WithPort(cfg.Port),
		mail.WithTimeout(cfg.Timeout),
		mail.WithSMTPAuth(mail.SMTPAuthAutoDiscover),
	}
	if cfg.Username != "" && cfg.Password != "" {
		opts = append(opts, mail.WithUsername(cfg.Username), mail.WithPassword(cfg.Password))
	}

	switch cfg.Port {
	case mail.DefaultPortSSL:
		opts = append(opts, mail.WithSSLPort(true))
	case mail.DefaultPortTLS:
		opts = append(opts, mail.WithTLSPortPolicy(mail.TLSMandatory))
	default:
		opts = append(opts, mail.WithTLSPortPolicy(mail.TLSOpportunistic))
	}

	client, err := mail.NewClient(cfg.Host, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create smtp client: %w", err)
	}

	return &smtpSender{client: client}, nil
}

func (s *smtpSender) Send(ctx context.Context, msg Message) error {
	message := mail.NewMsg()
	if err := message.From(msg.From.String()); err != nil {
		return fmt.Errorf("failed to set from address: %w", err)
	}
	if err := message.To(msg.RecipientEmails()...); err != nil {
		return fmt.Errorf("failed to set recipients: %w", err)
	}
	message.Subject(msg.Subject)
	message.SetBodyString(mail.TypeTextHTML, msg.HTMLBody)

	if msg.TextBody != "" {
		message.AddAlternativeString(mail.TypeTextPlain, msg.TextBody)
	}

	if err := s.client.DialAndSendWithContext(ctx, message); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}
	return nil
}
