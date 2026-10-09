package email

import (
	"context"
	"fmt"
	"time"

	mail "github.com/wneessen/go-mail"
)

type smtpSender struct {
	client *mail.Client
}

// Port 465 uses implicit TLS, 587 requires STARTTLS, anything else upgrades when the server offers it.
func newSMTPSender(host string, port int, username, password string) (*smtpSender, error) {
	opts := []mail.Option{mail.WithPort(port), mail.WithTimeout(10 * time.Second)}
	if username != "" {
		opts = append(opts,
			mail.WithSMTPAuth(mail.SMTPAuthAutoDiscover),
			mail.WithUsername(username),
			mail.WithPassword(password),
		)
	}
	switch port {
	case mail.DefaultPortSSL:
		opts = append(opts, mail.WithSSLPort(true))
	case mail.DefaultPortTLS:
		opts = append(opts, mail.WithTLSPortPolicy(mail.TLSMandatory))
	default:
		opts = append(opts, mail.WithTLSPortPolicy(mail.TLSOpportunistic))
	}

	client, err := mail.NewClient(host, opts...)
	if err != nil {
		return nil, fmt.Errorf("smtp client: %w", err)
	}
	return &smtpSender{client: client}, nil
}

// checkLogin connects and signs in once, nothing is sent.
func (s *smtpSender) checkLogin(ctx context.Context) error {
	c, err := s.client.DialToSMTPClientWithContext(ctx)
	if err != nil {
		return err
	}
	_ = s.client.CloseWithSMTPClient(c)
	return nil
}

func (s *smtpSender) Send(ctx context.Context, msg message) error {
	m := mail.NewMsg()
	if err := m.From(msg.From); err != nil {
		return fmt.Errorf("from address: %w", err)
	}
	if err := m.To(msg.To); err != nil {
		return fmt.Errorf("to address: %w", err)
	}
	m.Subject(msg.Subject)
	m.SetBodyString(mail.TypeTextHTML, msg.HTML)
	if err := s.client.DialAndSendWithContext(ctx, m); err != nil {
		return fmt.Errorf("smtp send: %w", err)
	}
	return nil
}
