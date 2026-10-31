package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nokku-sh/nokku/core/internal/config"
)

func TestWithHeadersCachePolicy(t *testing.T) {
	s := &Server{cfg: &config.Config{}}
	serve := func(h http.HandlerFunc) string {
		w := httptest.NewRecorder()
		s.withHeaders(h).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/nokku.v1.TargetService/ListTargets", nil))
		return w.Header().Get("Cache-Control")
	}

	assert.Equal(t, "no-store", serve(func(http.ResponseWriter, *http.Request) {}),
		"a read over GET must not be cached")
	assert.Equal(t, "public, max-age=3600", serve(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
	}), "a handler with its own policy keeps it")
}

// A browser keeps HSTS for a year, so only a client that is on https may get it, and nobody on localhost.
func TestHSTSIsOnlySetForAClientOnHTTPS(t *testing.T) {
	hsts := func(cfg *config.Config, proto string) string {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-Proto", proto)
		w := httptest.NewRecorder()
		(&Server{cfg: cfg}).withHeaders(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(w, req)
		return w.Header().Get("Strict-Transport-Security")
	}
	named := &config.Config{BaseURL: "nokku.example.com"}

	assert.NotEmpty(t, hsts(named, "https"), "a client on https")
	assert.Empty(t, hsts(named, "http"), "a client on http")
	assert.Empty(t, hsts(&config.Config{Port: "3000"}, "https"), "localhost")
}

// The scheme decides, not who sends it. A browser never sends X-Forwarded-Proto, so faking it only fools the core
// about the faker's own connection. A redirect through a proxy that names no scheme would never end.
func TestPlainHTTPIsSentToHTTPS(t *testing.T) {
	const proxy, stranger = "10.0.0.2:4242", "203.0.113.7:4242"
	proto := func(scheme string) http.Header { return http.Header{"X-Forwarded-Proto": {scheme}} }

	tests := []struct {
		name, path, peer string
		header           http.Header
		want             int
	}{
		{"the proxy for a client on https", "/", proxy, proto("https"), http.StatusOK},
		{"a proxy on a public address", "/", stranger, proto("https"), http.StatusOK},
		{"traefik for a websocket on https", "/terminal/ws", proxy, proto("wss"), http.StatusOK},
		{"a health probe", "/healthz", stranger, nil, http.StatusOK},
		{"a client that connects by itself", "/login?next=%2F", stranger, nil, http.StatusTemporaryRedirect},
		{"the proxy for a client on http", "/", proxy, proto("http"), http.StatusTemporaryRedirect},
		{"traefik for a websocket on http", "/terminal/ws", proxy, proto("ws"), http.StatusTemporaryRedirect},
		{
			"the proxy without the scheme", "/", proxy,
			http.Header{"X-Forwarded-For": {"203.0.113.9"}},
			http.StatusBadRequest,
		},
	}
	s := &Server{cfg: &config.Config{BaseURL: "nokku.example.com"}}
	served := s.withHTTPS(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			req.RemoteAddr = tt.peer
			if tt.header != nil {
				req.Header = tt.header
			}
			w := httptest.NewRecorder()
			served.ServeHTTP(w, req)
			assert.Equal(t, tt.want, w.Code)
			if tt.want == http.StatusTemporaryRedirect {
				assert.Equal(t, "https://nokku.example.com"+tt.path, w.Header().Get("Location"))
			}
		})
	}
}

// A browser takes http://localhost as secure, so the quick start and the dev server need no certificate.
func TestLocalhostIsServedPlain(t *testing.T) {
	s := &Server{cfg: &config.Config{Port: "3000"}}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.7:4242"
	s.withHTTPS(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}
