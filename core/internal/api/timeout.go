package api

import (
	"context"
	"time"

	"connectrpc.com/connect/v2"
)

// unaryTimeout caps unary calls, an earlier client deadline holds.
func unaryTimeout(next connect.ServerFunc) connect.ServerFunc {
	return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
		if spec.StreamType != connect.StreamTypeUnary {
			return next(ctx, spec, stream)
		}
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return next(ctx, spec, stream)
	}
}

// Streams end with the root ctx. Unary calls run on through the shutdown grace.
func streamsEndWith(root context.Context) connect.ServerInterceptor {
	return func(next connect.ServerFunc) connect.ServerFunc {
		return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
			if spec.StreamType == connect.StreamTypeUnary {
				return next(ctx, spec, stream)
			}
			ctx, release := endWith(ctx, root)
			defer release()
			return next(ctx, spec, stream)
		}
	}
}

// endWith returns a ctx that is also done when root is.
func endWith(ctx, root context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(root, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}
