package api

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/realip"
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
	require.NoError(t, realip.SetTrustedProxies([]string{"10.0.0.2"}))
	t.Cleanup(func() { _ = realip.SetTrustedProxies(nil) })
	hsts := func(cfg *config.Config, peer string, onTLS bool) string {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = peer
		req.Header.Set("X-Forwarded-Proto", "https")
		if onTLS {
			req.TLS = &tls.ConnectionState{}
			req.Header.Del("X-Forwarded-Proto")
		}
		w := httptest.NewRecorder()
		(&Server{cfg: cfg}).withHeaders(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(w, req)
		return w.Header().Get("Strict-Transport-Security")
	}
	named := &config.Config{BaseURL: "nokku.example.com"}

	assert.NotEmpty(t, hsts(named, "203.0.113.7:4242", true), "a client with TLS")
	assert.NotEmpty(t, hsts(named, "10.0.0.2:4242", false), "the proxy for a client on https")
	assert.Empty(t, hsts(named, "203.0.113.7:4242", false), "anyone can send the header")
	assert.Empty(t, hsts(&config.Config{Port: "3000"}, "203.0.113.7:4242", true), "localhost")
}

// Plain HTTP is for the proxy that holds the certificate. A session over it from anyone else would be readable
// on the way, and a redirect through a proxy that is not trusted would never end.
func TestPlainHTTPIsOnlyServedToATrustedProxy(t *testing.T) {
	require.NoError(t, realip.SetTrustedProxies([]string{"10.0.0.2"}))
	t.Cleanup(func() { _ = realip.SetTrustedProxies(nil) })
	const proxy, stranger = "10.0.0.2:4242", "203.0.113.7:4242"
	https := http.Header{"X-Forwarded-Proto": {"https"}}

	tests := []struct {
		name, path, peer string
		header           http.Header
		tls              bool
		want             int
	}{
		{"a client with TLS", "/", stranger, nil, true, http.StatusOK},
		{"the proxy for a client on https", "/", proxy, https, false, http.StatusOK},
		{"a health probe", "/healthz", stranger, nil, false, http.StatusOK},
		{"a client without TLS", "/login?next=%2F", stranger, nil, false, http.StatusTemporaryRedirect},
		{
			"the proxy for a client on http", "/", proxy,
			http.Header{"X-Forwarded-Proto": {"http"}},
			false, http.StatusTemporaryRedirect,
		},
		{"a proxy that is not trusted", "/", stranger, https, false, http.StatusBadRequest},
		{
			"the proxy without the scheme", "/", proxy,
			http.Header{"X-Forwarded-For": {"203.0.113.9"}},
			false, http.StatusBadRequest,
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
			if tt.tls {
				req.TLS = &tls.ConnectionState{}
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
