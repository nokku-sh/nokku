package api

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/entitlement"
)

func TestWithLogger(t *testing.T) {
	var out bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&out, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	serve := func(mode entitlement.Mode, status int, target string) string {
		out.Reset()
		s := &Server{cfg: &config.Config{Entitlements: entitlement.NewService(nil, nil, mode)}}
		s.withLogger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.URL.Path = "/index.html" // what the static handler does
			w.WriteHeader(status)
		})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, target, nil))
		return out.String()
	}

	const callback = "/oidc/callback?code=s3cret&state=xyz"

	assert.Empty(t, serve(entitlement.ModeSaaS, http.StatusOK, callback), "the SaaS logs no successful request")
	assert.Empty(t, serve(entitlement.ModeSaaS, http.StatusNotFound, callback), "nor a client error")
	failed := serve(entitlement.ModeSaaS, http.StatusInternalServerError, callback)
	assert.Contains(t, failed, "GET /oidc/callback => HTTP 500", "a server error is always logged")
	assert.NotContains(t, failed, "s3cret", "the query string must never be logged")

	line := serve(entitlement.ModeSelfHosted, http.StatusOK, callback)
	assert.Contains(t, line, "GET /oidc/callback => HTTP 200", "a self-hosted instance logs every request")
	assert.NotContains(t, line, "s3cret", "the query string must never be logged")
	assert.Empty(t, serve(entitlement.ModeSelfHosted, http.StatusOK, "/_app/immutable/chunks/a.js"),
		"served assets stay out of the log")
	assert.Contains(t, serve(entitlement.ModeSelfHosted, http.StatusNotFound, "/_app/immutable/chunks/a.js"),
		"HTTP 404", "a missing asset does not")
}

func TestWithRecover(t *testing.T) {
	s := &Server{cfg: &config.Config{}}

	rec := httptest.NewRecorder()
	s.withRecover(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/avatars/x", nil))
	assert.Equal(t, http.StatusInternalServerError, rec.Code, "a handler panic becomes a 500")
	assert.NotContains(t, rec.Body.String(), "boom", "the panic value must not reach the client")

	assert.PanicsWithValue(t, http.ErrAbortHandler, func() {
		s.withRecover(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic(http.ErrAbortHandler)
		})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}, "an intentional abort must pass through")
}
