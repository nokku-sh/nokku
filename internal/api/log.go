package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/connect"
)

type LogInterceptor struct {
	debug bool
}

func NewLogInterceptor(debug bool) *LogInterceptor {
	return &LogInterceptor{debug: debug}
}

func (l *LogInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		start := time.Now()
		res, err := next(ctx, req)
		duration := time.Since(start)

		attrs := rpcAttrs(req.Peer().Protocol, req.Spec().Procedure, duration)
		if err != nil {
			attrs = append(
				attrs,
				slog.String("code", connect.CodeOf(err).String()),
				slog.String("error_type", fmt.Sprintf("%T", err)),
			)
			if isServerError(connect.CodeOf(err)) {
				slog.LogAttrs(ctx, slog.LevelError, "rpc failed", attrs...)
			} else {
				slog.LogAttrs(ctx, slog.LevelDebug, "rpc", attrs...)
			}
		} else if l.debug {
			slog.LogAttrs(ctx, slog.LevelDebug, "rpc", attrs...)
		}

		return res, err
	}
}

func (l *LogInterceptor) WrapStreamingClient(
	next connect.StreamingClientFunc,
) connect.StreamingClientFunc {
	return next
}

func (l *LogInterceptor) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		start := time.Now()
		err := next(ctx, conn)
		duration := time.Since(start)

		attrs := rpcAttrs(conn.Peer().Protocol, conn.Spec().Procedure, duration)
		if err != nil {
			attrs = append(
				attrs,
				slog.String("code", connect.CodeOf(err).String()),
				slog.String("error_type", fmt.Sprintf("%T", err)),
			)
			if isServerError(connect.CodeOf(err)) {
				slog.LogAttrs(ctx, slog.LevelError, "stream failed", attrs...)
			} else {
				slog.LogAttrs(ctx, slog.LevelDebug, "stream", attrs...)
			}
		} else if l.debug {
			slog.LogAttrs(ctx, slog.LevelDebug, "stream", attrs...)
		}

		return err
	}
}

func rpcAttrs(protocol, procedure string, duration time.Duration) []slog.Attr {
	attrs := []slog.Attr{
		slog.String("procedure", procedure),
		slog.String("protocol", protocol),
		slog.Duration("duration", duration),
	}
	return attrs
}

// responseWriter wraps [http.ResponseWriter] to capture the status code.
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

func (s *Server) WithLogger(next http.Handler) http.Handler {
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
