package api

import (
	"context"
	"time"

	"connectrpc.com/connect"
)

func NewTimeoutInterceptor() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if _, hasDeadline := ctx.Deadline(); hasDeadline {
				return next(ctx, req)
			}

			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			return next(ctx, req)
		}
	}
}
