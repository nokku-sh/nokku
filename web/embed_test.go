package web

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMissingAssetIsNotFound(t *testing.T) {
	w := httptest.NewRecorder()
	Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/_app/immutable/chunks/gone.js", nil))
	assert.Equal(t, http.StatusNotFound, w.Code, "a missing chunk must not fall back to the index page")
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"), "the 404 must not be cached")
}

func TestAssetIsServedAsItself(t *testing.T) {
	var chunk string
	err := fs.WalkDir(StaticFS, uiRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if chunk == "" && !d.IsDir() && strings.HasSuffix(p, ".js") {
			chunk = strings.TrimPrefix(p, uiRoot)
		}
		return nil
	})
	require.NoError(t, err)
	if chunk == "" {
		t.Skip("frontend not built, run task build:ui")
	}

	w := httptest.NewRecorder()
	Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, chunk, nil))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "javascript", "%s came back as a page", chunk)
}
