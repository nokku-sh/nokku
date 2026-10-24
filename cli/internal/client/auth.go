package client

import (
	"context"

	"connectrpc.com/connect/v2"
)

// callTimeout bounds every unary call. The relay is a stream and lives as long as the ssh session.
func callTimeout(next connect.ClientFunc) connect.ClientFunc {
	return func(ctx context.Context, spec connect.Spec) (connect.ClientStream, error) {
		if _, ok := ctx.Deadline(); ok || spec.StreamType != connect.StreamTypeUnary {
			return next(ctx, spec)
		}
		ctx, cancel := context.WithTimeout(ctx, syncTimeout)
		stream, err := next(ctx, spec)
		if err != nil {
			cancel()
			return nil, err
		}
		return &cancelOnClose{ClientStream: stream, cancel: cancel}, nil
	}
}

// cancelOnClose ends the call's timeout with the call. A unary call always closes its stream.
type cancelOnClose struct {
	connect.ClientStream

	cancel context.CancelFunc
}

func (s *cancelOnClose) Close() error {
	defer s.cancel()
	return s.ClientStream.Close()
}

type bearerAuth struct {
	token string
	ua    string
}

func (a *bearerAuth) intercept(next connect.ClientFunc) connect.ClientFunc {
	return func(ctx context.Context, spec connect.Spec) (connect.ClientStream, error) {
		info, _ := connect.CallInfoForClientContext(ctx)
		info.RequestHeader().Set("Authorization", "Bearer "+a.token)
		if a.ua != "" {
			info.RequestHeader().Set("User-Agent", a.ua)
		}
		return next(ctx, spec)
	}
}
