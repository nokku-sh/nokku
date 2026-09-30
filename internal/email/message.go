package email

import "context"

type message struct {
	From    string
	To      string
	Subject string
	HTML    string
}

type sender interface {
	Send(ctx context.Context, msg message) error
}

type noopSender struct{}

func (noopSender) Send(context.Context, message) error { return nil }
