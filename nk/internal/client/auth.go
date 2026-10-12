package client

import (
	"context"
	"net/http"

	"connectrpc.com/connect"
)

// bearerAuth attaches the service-account API key and the client User-Agent.
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
