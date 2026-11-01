package api

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
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

// withLogger logs server failures only, never the query, it can carry tokens.
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

// withRecover covers plain HTTP routes, recoverRPC the connect handlers.
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
