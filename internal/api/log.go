package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/nokku-sh/nokku/internal/entitlement"
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

// withLogger writes one line per request in the style of chi's httplog. It
// logs the path only: query strings carry OAuth codes, one-time tokens and
// Connect GET messages.
func (s *Server) withLogger(next http.Handler) http.Handler {
	// The SaaS logs failures only, anything more is noise across tenants. A
	// self-hosted instance logs every request.
	floor := slog.LevelError
	if s.cfg.Debug || s.cfg.Entitlements.Mode() == entitlement.ModeSelfHosted {
		floor = slog.LevelInfo
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		// The static handler rewrites the path to the file it serves.
		path := r.URL.Path

		next.ServeHTTP(rw, r)
		duration := time.Since(start)

		level := slog.LevelInfo
		switch {
		case rw.statusCode >= 500:
			level = slog.LevelError
		case rw.statusCode >= 400:
			level = slog.LevelWarn
		}
		if level < floor || (level == slog.LevelInfo && !s.cfg.Debug && quietPath(path)) {
			return
		}
		slog.LogAttrs(r.Context(), level,
			fmt.Sprintf("%s %s => HTTP %d (%s)", r.Method, path, rw.statusCode, duration.Round(time.Microsecond)),
			slog.String("method", r.Method),
			slog.String("path", path),
			slog.Int("status", rw.statusCode),
			slog.Duration("duration", duration),
		)
	})
}

// quietPath is a request nobody wants a line for when it succeeds.
func quietPath(path string) bool {
	return path == "/healthz" || strings.HasPrefix(path, "/_app/")
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
