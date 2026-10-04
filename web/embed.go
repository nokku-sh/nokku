// Package web embeds the built UI and email templates. Both directories hold
// a committed .gitkeep so the Go build works without node.
package web

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"

	"github.com/vearutop/statigz"
	"github.com/vearutop/statigz/brotli"
)

//go:embed all:email/out
var EmailFS embed.FS

//go:embed all:ui/build
var StaticFS embed.FS

// Where the UI sits inside StaticFS.
const uiRoot = "ui/build"

// Handler serves the embedded SPA.
func Handler() http.Handler {
	pinMimeTypes()
	files := statigz.FileServer(StaticFS, brotli.AddEncoding, statigz.FSPrefix(uiRoot))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if p != "/" && !exists(p) {
			switch {
			case exists(p + ".html"):
				p += ".html"
			case strings.HasPrefix(p, "/_app/"):
				// A build file that is gone, like a chunk from before a
				// deploy. The index page would reach the browser as broken JS.
				w.Header().Set("Cache-Control", "no-store")
				http.NotFound(w, r)
				return
			default:
				p = "/"
			}
		}
		r.URL.Path = p
		w.Header().Set("Cache-Control", cachePolicy(p))
		files.ServeHTTP(w, r)
	})
}

// pinMimeTypes keeps content types host independent.
func pinMimeTypes() {
	_ = mime.AddExtensionType(".txt", "text/plain; charset=utf-8")
	_ = mime.AddExtensionType(".ico", "image/x-icon")
	_ = mime.AddExtensionType(".webmanifest", "application/manifest+json")
	_ = mime.AddExtensionType(".woff", "font/woff")
	_ = mime.AddExtensionType(".woff2", "font/woff2")
}

func exists(p string) bool {
	st, err := fs.Stat(StaticFS, path.Join(uiRoot, p))
	return err == nil && !st.IsDir()
}

func cachePolicy(p string) string {
	switch {
	case strings.HasPrefix(p, "/_app/immutable/"):
		return "public, max-age=31536000, immutable"
	case p == "/" || strings.HasSuffix(p, ".html") || p == "/service-worker.js" || p == "/_app/version.json":
		return "no-cache"
	default:
		return "public, max-age=3600"
	}
}
