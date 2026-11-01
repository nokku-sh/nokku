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

// Browsers keep HSTS for a year, so it goes to https clients, not localhost.
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

// The scheme decides, not who sends it. Faking X-Forwarded-Proto only fools the
// core about the faker's own connection. A redirect through a proxy that names
// no scheme would never end.
func TestPlainHTTPIsSentToHTTPS(t *testing.T) {
	const proxy, stranger = "10.0.0.2:4242", "203.0.113.7:4242"
	proto := func(scheme string) http.Header { return http.Header{"X-Forwarded-Proto": {scheme}} }

	tests := []struct {
		name, path, peer string
		header           http.Header
		want             int
		location         string
	}{
		{"the proxy for a client on https", "/", proxy, proto("https"), http.StatusOK, ""},
		{"a proxy on a public address", "/", stranger, proto("https"), http.StatusOK, ""},
		{"traefik for a websocket on https", "/terminal/ws", proxy, proto("wss"), http.StatusOK, ""},
		{"a health probe", "/healthz", stranger, nil, http.StatusOK, ""},
		{
			"a client that connects by itself", "/login?next=%2F", stranger, nil,
			http.StatusTemporaryRedirect, "https://nokku.example.com/login?next=%2F",
		},
		{
			"the proxy for a client on http", "/", proxy, proto("http"),
			http.StatusTemporaryRedirect, "https://nokku.example.com/",
		},
		{
			"traefik for a websocket on http", "/terminal/ws", proxy, proto("ws"),
			http.StatusTemporaryRedirect, "https://nokku.example.com/terminal/ws",
		},
		{
			"the proxy without the scheme", "/", proxy,
			http.Header{"X-Forwarded-For": {"203.0.113.9"}},
			http.StatusBadRequest, "",
		},
	}
	s := &Server{cfg: &config.Config{BaseURL: "nokku.example.com"}}
	served := s.withHTTPS(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			req.RemoteAddr = tt.peer
			req.Header = tt.header
			w := httptest.NewRecorder()
			served.ServeHTTP(w, req)
			assert.Equal(t, tt.want, w.Code)
			assert.Equal(t, tt.location, w.Header().Get("Location"))
		})
	}
}

// Browsers trust http://localhost, so quick start and dev need no certificate.
func TestLocalhostIsServedPlain(t *testing.T) {
	s := &Server{cfg: &config.Config{Port: "3000"}}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.7:4242"
	s.withHTTPS(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}
