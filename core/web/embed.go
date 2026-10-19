// Package web embeds the built UI. A committed .gitkeep lets the Go build work without node.
package web

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"io/fs"
	"mime"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/vearutop/statigz"
	"github.com/vearutop/statigz/brotli"
)

//go:generate pnpm install
//go:generate pnpm build
// The build empties build/, the placeholder lets go build work without node.
//go:generate touch build/.gitkeep
//go:embed all:build
var staticFS embed.FS

// Where the UI sits inside staticFS.
const uiRoot = "build"

// Handler serves the embedded SPA, or what the Vite dev server hands out. The browser only talks to this server.
func Handler() http.Handler {
	if dev := os.Getenv("NOKKU_DEV_UI"); dev != "" {
		return devProxy(dev)
	}
	pinMimeTypes()
	files := statigz.FileServer(staticFS, brotli.AddEncoding, statigz.FSPrefix(uiRoot))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if p != "/" && !exists(p) {
			switch {
			case exists(p + ".html"):
				p += ".html"
			case strings.HasPrefix(p, "/_app/"):
				// A chunk from before a deploy is gone. The index page would reach the browser as broken JS.
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

func devProxy(target string) http.Handler {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		panic("NOKKU_DEV_UI is not a url: " + target)
	}
	return &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(u)
			r.SetXForwarded()
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			http.Error(w, "No Vite at "+target+", run pnpm dev in web. "+err.Error(), http.StatusBadGateway)
		},
	}
}

var inlineScript = regexp.MustCompile(`(?s)<script([^>]*)>(.*?)</script>`)

// InlineScriptHashes allows SvelteKit's inline bootstrap by hash, so the policy needs no 'unsafe-inline'.
var InlineScriptHashes = sync.OnceValue(func() []string {
	var hashes []string
	_ = fs.WalkDir(staticFS, uiRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".html") {
			return err
		}
		page, err := staticFS.ReadFile(p)
		if err != nil {
			return err
		}
		for _, m := range inlineScript.FindAllSubmatch(page, -1) {
			if bytes.Contains(m[1], []byte("src=")) {
				continue
			}
			sum := sha256.Sum256(m[2])
			if hash := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"; !slices.Contains(hashes, hash) {
				hashes = append(hashes, hash)
			}
		}
		return nil
	})
	return hashes
})

// pinMimeTypes keeps content types host independent.
func pinMimeTypes() {
	_ = mime.AddExtensionType(".txt", "text/plain; charset=utf-8")
	_ = mime.AddExtensionType(".ico", "image/x-icon")
	_ = mime.AddExtensionType(".webmanifest", "application/manifest+json")
	_ = mime.AddExtensionType(".woff", "font/woff")
	_ = mime.AddExtensionType(".woff2", "font/woff2")
}

func exists(p string) bool {
	st, err := fs.Stat(staticFS, path.Join(uiRoot, p))
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
