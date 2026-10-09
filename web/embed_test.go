package web

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMissingAssetIsNotFound(t *testing.T) {
	w := httptest.NewRecorder()
	Handler(&url.URL{}).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/_app/immutable/chunks/gone.js", nil))
	assert.Equal(t, http.StatusNotFound, w.Code, "a missing chunk must not fall back to the index page")
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"), "the 404 must not be cached")
}

func TestAssetIsServedAsItself(t *testing.T) {
	var chunk string
	err := fs.WalkDir(staticFS, uiRoot, func(p string, d fs.DirEntry, err error) error {
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
	Handler(&url.URL{}).ServeHTTP(w, httptest.NewRequest(http.MethodGet, chunk, nil))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "javascript", "%s came back as a page", chunk)
}

// The policy has no 'unsafe-inline', so a page whose inline script is not in
// the list would not start.
func TestInlineScriptHashesCoverThePages(t *testing.T) {
	index, err := staticFS.ReadFile(uiRoot + "/index.html")
	if err != nil {
		t.Skip("frontend not built, run task build:ui")
	}
	hashes := InlineScriptHashes()
	require.NotEmpty(t, hashes, "the built pages start from an inline script")

	inline := 0
	for _, m := range inlineScript.FindAllSubmatch(index, -1) {
		if bytes.Contains(m[1], []byte("src=")) {
			continue
		}
		inline++
		sum := sha256.Sum256(m[2])
		assert.Contains(t, hashes, "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'")
	}
	assert.Positive(t, inline, "index.html has no inline script, the pattern no longer matches")
}
