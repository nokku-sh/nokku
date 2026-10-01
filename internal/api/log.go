package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"connectrpc.com/connect"
)

type logInterceptor struct {
	debug bool
}

func newLogInterceptor(debug bool) *logInterceptor {
	return &logInterceptor{debug: debug}
}

func (l *logInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		start := time.Now()
		res, err := next(ctx, req)
		l.log(ctx, "rpc", req.Peer().Protocol, req.Spec().Procedure, time.Since(start), err)
		return res, err
	}
}

func (l *logInterceptor) WrapStreamingClient(
	next connect.StreamingClientFunc,
) connect.StreamingClientFunc {
	return next
}

func (l *logInterceptor) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		start := time.Now()
		err := next(ctx, conn)
		l.log(ctx, "stream", conn.Peer().Protocol, conn.Spec().Procedure, time.Since(start), err)
		return err
	}
}

func (l *logInterceptor) log(
	ctx context.Context,
	msg, protocol, procedure string,
	duration time.Duration,
	err error,
) {
	attrs := []slog.Attr{
		slog.String("procedure", procedure),
		slog.String("protocol", protocol),
		slog.Duration("duration", duration),
	}
	switch {
	case err != nil:
		code := connect.CodeOf(err)
		attrs = append(attrs, slog.String("code", code.String()))
		if isServerError(code) {
			slog.LogAttrs(ctx, slog.LevelError, msg+" failed", attrs...)
		} else {
			slog.LogAttrs(ctx, slog.LevelDebug, msg, attrs...)
		}
	case l.debug:
		slog.LogAttrs(ctx, slog.LevelDebug, msg, attrs...)
	}
}

type responseWriter struct {
	http.ResponseWriter

	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

func (rw *responseWriter) Flush() {
	rc := http.NewResponseController(rw.ResponseWriter)
	_ = rc.Flush()
}

func (s *Server) withLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(rw, r)
		duration := time.Since(start)

		attrs := []slog.Attr{
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", rw.statusCode),
			slog.Duration("duration", duration),
		}
		switch {
		case rw.statusCode >= 500:
			slog.LogAttrs(r.Context(), slog.LevelError, "http failed", attrs...)
		case s.cfg.Debug:
			slog.LogAttrs(r.Context(), slog.LevelDebug, "http", attrs...)
		}
	})
}

// withRecover covers the plain HTTP routes, connect handlers recover on
// their own. It sits inside withLogger so the 500 is logged like any other.
func (s *Server) withRecover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			p := recover()
			if p == nil {
				return
			}
			// net/http uses this to abort a response on purpose.
			if err, ok := p.(error); ok && errors.Is(err, http.ErrAbortHandler) {
				panic(p)
			}
			attrs := []slog.Attr{
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("panic_type", fmt.Sprintf("%T", p)),
			}
			if s.cfg.Debug {
				attrs = append(attrs, slog.String("stack", string(debug.Stack())))
			}
			slog.LogAttrs(r.Context(), slog.LevelError, "http panic recovered", attrs...)
			writeJSONError(w, http.StatusInternalServerError, "internal error")
		}()
		next.ServeHTTP(w, r)
	})
}

func isServerError(code connect.Code) bool {
	switch code {
	case connect.CodeInternal, connect.CodeUnknown, connect.CodeUnavailable,
		connect.CodeDataLoss, connect.CodeDeadlineExceeded:
		return true
	case connect.CodeCanceled, connect.CodeInvalidArgument, connect.CodeNotFound,
		connect.CodeAlreadyExists, connect.CodePermissionDenied, connect.CodeResourceExhausted,
		connect.CodeFailedPrecondition, connect.CodeAborted, connect.CodeOutOfRange,
		connect.CodeUnimplemented, connect.CodeUnauthenticated:
		return false
	default:
		return false
	}
}
