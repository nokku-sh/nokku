package api

import (
	"context"
	"net/http"
	"time"

	"connectrpc.com/connect/v2"
)

const unaryTime = 10 * time.Second

// unaryTimeout caps unary calls, an earlier client deadline holds.
func unaryTimeout(next connect.ServerFunc) connect.ServerFunc {
	return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
		if spec.StreamType != connect.StreamTypeUnary {
			return next(ctx, spec, stream)
		}
		ctx, cancel := context.WithTimeout(ctx, unaryTime)
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

// unaryTimeout cannot interrupt a body read.
func bodyDeadline(timeout time.Duration) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if unaryProcedures[r.URL.Path] && r.Body != http.NoBody {
				_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(timeout))
			}
			h.ServeHTTP(w, r)
		})
	}
}
