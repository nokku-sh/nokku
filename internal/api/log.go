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
)

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

// quietHandshakes is the handler for the lines net/http writes itself. A
// client that leaves before its first request is one of them for every
// connection: a browser that does not trust the certificate yet, or a
// scanner. Those go to debug.
type quietHandshakes struct{ slog.Handler }

func (h quietHandshakes) Handle(ctx context.Context, r slog.Record) error {
	if strings.HasPrefix(r.Message, "http: TLS handshake error") ||
		strings.HasPrefix(r.Message, "http2: server: error reading preface") {
		if !h.Enabled(ctx, slog.LevelDebug) {
			return nil
		}
		r.Level = slog.LevelDebug
	}
	return h.Handler.Handle(ctx, r)
}

// withLogger writes a line for a request the server failed, nothing else.
// Traces go to OTel, denied and malformed calls land in the audit log. It
// logs the path only: query strings carry OAuth codes and one-time tokens.
func (s *Server) withLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		// The static handler rewrites the path to the file it serves.
		path := r.URL.Path

		next.ServeHTTP(rw, r)
		if rw.statusCode < 500 {
			return
		}
		slog.LogAttrs(r.Context(), slog.LevelError, "request failed",
			slog.String("method", r.Method),
			slog.String("path", path),
			slog.Int("status", rw.statusCode),
			slog.Duration("duration", time.Since(start)),
		)
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
