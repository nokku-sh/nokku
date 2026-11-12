package api

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/nokku-sh/nokku/core/web"
)

// The UI is same-origin, so no CORS. The terminal websocket checks its origin.
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
	protected := cop.Handler(h)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// An external sender. SSO has single-use state.
		if r.URL.Path == "/oidc/callback" {
			h.ServeHTTP(w, r)
			return
		}

		protected.ServeHTTP(w, r)
	})
}

func (s *Server) withHeaders(h http.Handler) http.Handler {
	// Only the bootstrap runs inline, injected code would reach the terminal.
	pinned := web.InlineScriptHashes()
	workers := ""
	if web.DevUI() != "" {
		// The pages of the Vite dev server change with every edit.
		pinned = []string{"'unsafe-inline'"}
		// Vite pings from a blob worker, to reload once the server is back.
		workers = " worker-src 'self' blob:;"
	}
	// The recording player compiles WebAssembly.
	scripts := strings.Join(append([]string{"'self'", "'wasm-unsafe-eval'"}, pinned...), " ")
	// The avatar cropper shows the picked file through a blob URL.
	csp := "default-src 'self'; script-src " + scripts +
		"; img-src 'self' data: blob: https:; style-src 'self' 'unsafe-inline'; font-src 'self' data:;" + workers

	// HSTS on localhost holds for every port and breaks other dev servers.
	hsts := s.cfg.Hostname() != "localhost"

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", csp)

		// No API response may be cached. The static handler sets its own.
		if r.Method == http.MethodGet {
			w.Header().Set("Cache-Control", "no-store")
		}

		// Sent whatever the scheme, a browser takes HSTS only over https.
		if hsts {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		h.ServeHTTP(w, r)
	})
}
