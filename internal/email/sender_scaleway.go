package email

import (
	"context"
	"fmt"

	tem "github.com/scaleway/scaleway-sdk-go/api/tem/v1alpha1"
	"github.com/scaleway/scaleway-sdk-go/scw"
)

type scalewaySender struct {
	api *tem.API
}

func newScalewaySender() (*scalewaySender, error) {
	client, err := scw.NewClient(scw.WithEnv())
	if err != nil {
		return nil, fmt.Errorf("create scaleway client: %w", err)
	}

	return &scalewaySender{api: tem.NewAPI(client)}, nil
}

func (s *scalewaySender) Send(ctx context.Context, msg Message) error {
	from := &tem.CreateEmailRequestAddress{
		Email: msg.From.Email,
	}
	if msg.From.Name != "" {
		from.Name = &msg.From.Name
	}

	req := &tem.CreateEmailRequest{
		From:    from,
		Subject: msg.Subject,
		HTML:    msg.HTMLBody,
		Text:    msg.TextBody,
	}

	for _, addr := range msg.To {
		a := &tem.CreateEmailRequestAddress{Email: addr.Email}
		if addr.Name != "" {
			a.Name = &addr.Name
		}
		req.To = append(req.To, a)
	}

	for k, v := range msg.Headers {
		req.AdditionalHeaders = append(req.AdditionalHeaders, &tem.CreateEmailRequestHeader{
			Key:   k,
			Value: v,
		})
	}

	_, err := s.api.CreateEmail(req, scw.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("send via scaleway tem: %w", err)
	}

	return nil
}
