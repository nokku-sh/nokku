package api

import (
	"context"
	"time"

	"connectrpc.com/connect"
)

// newTimeoutInterceptor caps every unary call. A deadline the client asked for only counts when it is earlier.
func newTimeoutInterceptor() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			return next(ctx, req)
		}
	}
}

// streamInterceptorFunc is connect.UnaryInterceptorFunc for the handler side of a stream.
type streamInterceptorFunc func(connect.StreamingHandlerFunc) connect.StreamingHandlerFunc

func (f streamInterceptorFunc) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc { return next }

func (f streamInterceptorFunc) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (f streamInterceptorFunc) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return f(next)
}

// newStreamEndInterceptor ends every stream with the root ctx. Unary calls run on through the shutdown grace.
func newStreamEndInterceptor(root context.Context) connect.Interceptor {
	return streamInterceptorFunc(func(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
		return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
			ctx, release := endWith(ctx, root)
			defer release()
			return next(ctx, conn)
		}
	})
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
