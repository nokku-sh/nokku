package api

import (
	"context"
	"time"

	"connectrpc.com/connect"
)

func NewTimeoutInterceptor() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			// Skip streaming RPCs (Connect bidi streams, server streams, client streams)
			// — they live longer than any reasonable unary timeout.
			if req.Spec().StreamType != connect.StreamTypeUnary {
				return next(ctx, req)
			}

			// Skip if client already provided a deadline
			if _, hasDeadline := ctx.Deadline(); hasDeadline {
				return next(ctx, req)
			}

			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			return next(ctx, req)
		}
	}
}
