package email

import (
	"context"
	"strings"
)

type Address struct {
	Name  string
	Email string
}

func (a Address) String() string {
	if a.Name == "" {
		return a.Email
	}
	return a.Name + " <" + a.Email + ">"
}

type Message struct {
	From     Address
	To       []Address
	Subject  string
	HTMLBody string
	TextBody string
	Headers  map[string]string
	Tags     map[string]string
}

func (m Message) RecipientEmails() []string {
	if len(m.To) == 0 {
		return nil
	}

	recipients := make([]string, 0, len(m.To))
	for _, addr := range m.To {
		if email := strings.TrimSpace(addr.Email); email != "" {
			recipients = append(recipients, email)
		}
	}
	return recipients
}

type Sender interface {
	Send(ctx context.Context, msg Message) error
}

type SenderFunc func(ctx context.Context, msg Message) error

func (f SenderFunc) Send(ctx context.Context, msg Message) error {
	return f(ctx, msg)
}
