package email

import "context"

// Message is one HTML email to a single recipient.
type Message struct {
	From    string
	To      string
	Subject string
	HTML    string
}

// Sender delivers a message. SMTP in production, a fake in tests.
type Sender interface {
	Send(ctx context.Context, msg Message) error
}

type noopSender struct{}

func (noopSender) Send(context.Context, Message) error { return nil }
