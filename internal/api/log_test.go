package api

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nokku-sh/nokku/internal/config"
)

// Only a failed request gets a line. The rest is traced, or audited.
func TestWithLogger(t *testing.T) {
	var out bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&out, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	serve := func(status int, target string) string {
		out.Reset()
		s := &Server{cfg: &config.Config{}}
		s.withLogger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.URL.Path = "/index.html" // what the static handler does
			w.WriteHeader(status)
		})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, target, nil))
		return out.String()
	}

	const callback = "/oidc/callback?code=s3cret&state=xyz"

	assert.Empty(t, serve(http.StatusOK, callback), "a successful request is not logged")
	assert.Empty(t, serve(http.StatusNotFound, callback), "nor a client error")
	failed := serve(http.StatusInternalServerError, callback)
	assert.Contains(t, failed, "path=/oidc/callback", "a server error is logged")
	assert.Contains(t, failed, "status=500")
	assert.NotContains(t, failed, "s3cret", "the query string must never be logged")
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
