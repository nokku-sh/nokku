package api

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	connectcors "connectrpc.com/cors"
	"github.com/rs/cors"
)

func (s *Server) WithCORS(h http.Handler) http.Handler {
	return cors.New(cors.Options{
		AllowedOrigins:   []string{s.cfg.FullURL()},
		AllowedMethods:   connectcors.AllowedMethods(),
		ExposedHeaders:   connectcors.ExposedHeaders(),
		AllowedHeaders:   connectcors.AllowedHeaders(),
		AllowCredentials: true,
		MaxAge:           int(2 * time.Hour / time.Second),
	}).Handler(h)
}

func (s *Server) WithCSRF(h http.Handler) http.Handler {
	cop := http.NewCrossOriginProtection()
	if err := cop.AddTrustedOrigin(s.cfg.FullURL()); err != nil {
		panic(err)
	}
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("CSRF check failed"))
	}))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip CSRF for webhooks and OAuth callbacks (they originate from external servers)
		if r.URL.Path == "/saml/acs" ||
			r.URL.Path == "/oauth/callback" ||
			strings.HasPrefix(r.URL.Path, "/webhooks/") {
			slog.Debug("skipping CSRF check", "path", r.URL.Path)
			h.ServeHTTP(w, r)
			return
		}

		// Apply CSRF protection for other routes
		cop.Handler(h).ServeHTTP(w, r)
	})
}

func (s *Server) WithHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().
			Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; font-src 'self' data:;")

		if r.Method == http.MethodGet {
			if strings.HasPrefix(r.URL.Path, "/_app/") {
				w.Header().Set("Cache-Control", "public, max-age=604800, immutable")
			} else {
				w.Header().Set("Cache-Control", "no-store")
			}
		}

		// Only add HSTS if using HTTPS
		isSecure := r.Header.Get("X-Forwarded-Proto") == "https" || r.TLS != nil
		if isSecure {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		h.ServeHTTP(w, r)
	})
}
