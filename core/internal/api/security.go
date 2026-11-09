package api

import (
	"log/slog"
	"net"
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

// X-Forwarded-Proto is taken from anyone. A browser never sends it, so faking
// it only fools the core about the faker's own connection.
func (s *Server) withHTTPS(h http.Handler) http.Handler {
	// A browser takes http://localhost as secure, so no certificate is needed.
	if s.cfg.Hostname() == "localhost" {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			h.ServeHTTP(w, r)
			return
		}
		proto := r.Header.Get("X-Forwarded-Proto")
		if proto == "" && r.Header.Get("X-Forwarded-For") == "" {
			// A client that connects by itself.
			proto = "http"
		}
		// Traefik names a WebSocket upgrade ws or wss.
		switch proto {
		case "https", "wss":
			h.ServeHTTP(w, r)
		case "http", "ws":
			target := s.cfg.FullURL()
			if s.cfg.SaaS {
				// Every workspace of the hosted service has a host of its own.
				target = "https://" + r.Host
			}
			// #nosec G710 -- same host on https, only the path is the client's
			http.Redirect(w, r, target+r.URL.RequestURI(), http.StatusTemporaryRedirect)
		default:
			// A redirect would come back through the same proxy.
			peer, _, _ := net.SplitHostPort(r.RemoteAddr)
			http.Error(w, "Nokku is served over https. This request came through a proxy at "+peer+
				" that does not say which scheme the client used. It has to send X-Forwarded-Proto.",
				http.StatusBadRequest)
		}
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

		// Harmless if faked, a browser takes HSTS only over https.
		if hsts && r.Header.Get("X-Forwarded-Proto") == "https" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		h.ServeHTTP(w, r)
	})
}
