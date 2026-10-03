package api

import (
	"log/slog"
	"net/http"
	"strings"
)

// withCSRF is the only cross-origin gate. The UI is served from the same
// origin, so there is no CORS to configure.
func (s *Server) withCSRF(h http.Handler) http.Handler {
	cop := http.NewCrossOriginProtection()
	if err := cop.AddTrustedOrigin(s.cfg.FullURL()); err != nil {
		panic(err)
	}
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Warn("csrf validation failed", "method", r.Method)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("CSRF check failed"))
	}))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Webhooks and SSO callbacks come from external servers, their
		// protection is the single-use flow state.
		if r.URL.Path == "/saml/acs" ||
			r.URL.Path == "/oauth/callback" ||
			r.URL.Path == "/oidc/callback" ||
			strings.HasPrefix(r.URL.Path, "/webhooks/") {
			slog.Debug("skipping CSRF check", "path", r.URL.Path)
			h.ServeHTTP(w, r)
			return
		}

		cop.Handler(h).ServeHTTP(w, r)
	})
}

func (s *Server) withHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		if r.Header.Get("X-Forwarded-Proto") == "https" || r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		h.ServeHTTP(w, r)
	})
}
