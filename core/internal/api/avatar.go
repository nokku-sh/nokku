package api

import (
	"bytes"
	"errors"
	"image"
	_ "image/gif" // register GIF decoder
	"image/jpeg"
	_ "image/png" // register PNG decoder
	"net/http"

	"golang.org/x/image/draw"

	"github.com/nokku-sh/nokku/core/internal/config"
)

const (
	// avatarSize covers the console's largest avatar at twice its size.
	avatarSize = 128
	// maxAvatarPixels guards against decompression bombs.
	maxAvatarPixels = 4000
)

var errNotAnImage = errors.New("not a JPEG, PNG or GIF image")

// avatarJPEG crops raw to its centered square and scales it to avatarSize, a JPEG of a few KB.
func avatarJPEG(raw []byte) ([]byte, error) {
	cfg, _, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		return nil, errNotAnImage
	}
	if cfg.Width > maxAvatarPixels || cfg.Height > maxAvatarPixels {
		return nil, errors.New("the image is larger than 4000 pixels on a side")
	}
	src, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, errNotAnImage
	}

	b := src.Bounds()
	side := min(b.Dx(), b.Dy())
	square := image.Rect(0, 0, side, side).Add(b.Min.Add(image.Pt((b.Dx()-side)/2, (b.Dy()-side)/2)))
	dst := image.NewRGBA(image.Rect(0, 0, avatarSize, avatarSize))
	// JPEG has no transparency, a transparent PNG lands on white.
	draw.Draw(dst, dst.Bounds(), image.White, image.Point{}, draw.Src)
	draw.CatmullRom.Scale(dst, dst.Bounds(), src, square, draw.Over, nil)

	var out bytes.Buffer
	if err := jpeg.Encode(&out, dst, &jpeg.Options{Quality: 85}); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// serveAvatar runs behind a session. The host pins the workspace, so RLS keeps it to the users of that one.
func serveAvatar(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		row, err := cfg.Conn.Tenant().GetAvatar(r.Context(), r.PathValue("id"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/jpeg")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// users.picture carries the etag, so a new picture is a new URL.
		w.Header().Set("Cache-Control", "private, max-age=31536000, immutable")
		w.Header().Set("ETag", `"`+row.Etag+`"`)
		http.ServeContent(w, r, "", row.UpdatedAt, bytes.NewReader(row.Image))
	}
}
