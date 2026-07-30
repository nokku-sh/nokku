package email

import "context"

type NoopSender struct{}

func (NoopSender) Send(context.Context, Message) error {
	return nil
}
