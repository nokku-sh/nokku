package client

import (
	"context"
	"net/http"

	"connectrpc.com/connect/v2"
)

// callTimeout bounds every unary call. The relay is a stream and lives as long as the ssh session.
var callTimeout = connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if _, ok := ctx.Deadline(); !ok {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, syncTimeout)
			defer cancel()
		}
		return next(ctx, req)
	}
})

type bearerAuth struct {
	token string
	ua    string
}

func (a *bearerAuth) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		a.set(req.Header())
		return next(ctx, req)
	}
}

func (a *bearerAuth) WrapStreamingClient(
	next connect.StreamingClientFunc,
) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)
		a.set(conn.RequestHeader())
		return conn
	}
}

func (a *bearerAuth) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return next
}

func (a *bearerAuth) set(header http.Header) {
	header.Set("Authorization", "Bearer "+a.token)
	if a.ua != "" {
		header.Set("User-Agent", a.ua)
	}
}
