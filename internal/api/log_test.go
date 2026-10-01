package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nokku-sh/nokku/internal/config"
)

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
