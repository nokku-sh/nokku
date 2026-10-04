package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nokku-sh/nokku/internal/config"
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
