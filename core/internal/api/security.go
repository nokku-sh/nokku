package api

import (
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/nokku-sh/nokku/core/internal/realip"
	"github.com/nokku-sh/nokku/core/web"
)

// withCSRF is the only cross-origin gate. The UI is same-origin, so there is no CORS to configure.
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
		// Webhooks and SSO callbacks come from external servers, their protection is the single-use flow state.
		if r.URL.Path == "/oidc/callback" ||
			strings.HasPrefix(r.URL.Path, "/webhooks/") {
			h.ServeHTTP(w, r)
			return
		}

		protected.ServeHTTP(w, r)
	})
}

// withHTTPS serves plain HTTP only to a trusted proxy that holds the certificate, anyone else is sent to https.
func (s *Server) withHTTPS(h http.Handler) http.Handler {
	// A browser takes http://localhost as secure, so a try on this machine needs no certificate.
	if s.cfg.Hostname() == "localhost" {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proto := realip.Proto(r.Header, r.RemoteAddr)
		forwarded := r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("X-Forwarded-Proto") != ""
		switch {
		case r.TLS != nil, proto == "https", r.URL.Path == "/healthz":
			h.ServeHTTP(w, r)
		case proto == "http", !forwarded:
			target := s.cfg.FullURL()
			if s.cfg.SaaS {
				// Every workspace of the hosted service has a host of its own.
				target = "https://" + r.Host
			}
			// #nosec G710 -- the same host on https, only the path is the client's
			http.Redirect(w, r, target+r.URL.RequestURI(), http.StatusTemporaryRedirect)
		default:
			// A redirect would come back through the same proxy.
			peer, _, _ := net.SplitHostPort(r.RemoteAddr)
			http.Error(w, "Nokku is served over https. This request came in plain HTTP through a proxy at "+peer+
				". If that is your proxy, it has to be in NOKKU_TRUSTED_PROXIES and send X-Forwarded-Proto.",
				http.StatusBadRequest)
		}
	})
}

func (s *Server) withHeaders(h http.Handler) http.Handler {
	// Only the bootstrap of the built pages runs inline, an injected script would reach the web terminal.
	pinned := web.InlineScriptHashes()
	if os.Getenv("NOKKU_DEV_UI") != "" {
		// The pages of the Vite dev server change with every edit.
		pinned = []string{"'unsafe-inline'"}
	}
	// The recording player compiles WebAssembly.
	scripts := strings.Join(append([]string{"'self'", "'wasm-unsafe-eval'"}, pinned...), " ")
	csp := "default-src 'self'; script-src " + scripts +
		"; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; font-src 'self' data:;"

	// A browser keeps HSTS for localhost on every port, which would break whatever else is developed here.
	hsts := s.cfg.Hostname() != "localhost"

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", csp)

		// No API response may be cached. The static handler and the avatars set their own policy.
		if r.Method == http.MethodGet {
			w.Header().Set("Cache-Control", "no-store")
		}

		if hsts && (realip.Proto(r.Header, r.RemoteAddr) == "https" || r.TLS != nil) {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		h.ServeHTTP(w, r)
	})
}
