package api

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/nokku-sh/nokku/web"
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
		if r.URL.Path == "/oidc/callback" ||
			strings.HasPrefix(r.URL.Path, "/webhooks/") {
			h.ServeHTTP(w, r)
			return
		}

		cop.Handler(h).ServeHTTP(w, r)
	})
}

func (s *Server) withHeaders(h http.Handler) http.Handler {
	// No inline script runs but the bootstrap of the built pages. A script
	// injected into the UI would otherwise reach the web terminal.
	// The recording player compiles WebAssembly, which needs its own source.
	pinned := web.InlineScriptHashes()
	if s.cfg.UIDev.Host != "" {
		// The pages of the Vite dev server change with every edit.
		pinned = []string{"'unsafe-inline'"}
	}
	scripts := strings.Join(append([]string{"'self'", "'wasm-unsafe-eval'"}, pinned...), " ")
	csp := "default-src 'self'; script-src " + scripts +
		"; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; font-src 'self' data:;"

	// A browser keeps HSTS for localhost on every port, which would break
	// whatever else is developed on this machine.
	hsts := s.cfg.Hostname() != "localhost"

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", csp)

		// The UI reads over GET, and no API response may be cached. The static
		// handler and the avatars set their own policy.
		if r.Method == http.MethodGet {
			w.Header().Set("Cache-Control", "no-store")
		}

		if hsts && (r.Header.Get("X-Forwarded-Proto") == "https" || r.TLS != nil) {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		h.ServeHTTP(w, r)
	})
}
