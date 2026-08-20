package api

import (
	"bytes"
	"fmt"
	"image"
	_ "image/gif" // register GIF decoder
	"image/jpeg"
	_ "image/png" // register PNG decoder
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"golang.org/x/image/draw"

	"github.com/nokku-sh/nokku/internal/auth"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/storage"
)

const (
	maxAvatarSize = 5 << 20 // 5MB
	maxParts      = 10
)

func resizePicture(src image.Image) image.Image {
	dst := image.NewRGBA(image.Rect(0, 0, 256, 256))
	draw.CatmullRom.Scale(dst, dst.Bounds(), src, src.Bounds(), draw.Over, nil)
	return dst
}

func UploadAvatar(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())
		user, err := cfg.Conn.Q.GetUserByID(r.Context(), userID)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Failed to get identity")
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxAvatarSize+(10<<10))
		reader, err := r.MultipartReader()
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid multipart form")
			return
		}

		var file io.ReadSeeker
		for range maxParts {
			part, nextErr := reader.NextPart()
			if nextErr == io.EOF {
				break
			}
			if nextErr != nil {
				writeJSONError(w, http.StatusBadRequest, "failed to read upload")
				return
			}

			if part.FormName() != "picture" {
				_ = part.Close()
				continue
			}

			// +1 so reading exactly maxAvatarSize+1 bytes proves oversize.
			limited := io.LimitReader(part, maxAvatarSize+1)
			fileBytes, readErr := io.ReadAll(limited)
			_ = part.Close()
			if readErr != nil {
				writeJSONError(w, http.StatusBadRequest, "failed to read file")
				return
			}
			if int64(len(fileBytes)) > maxAvatarSize {
				writeJSONError(w, http.StatusBadRequest, "file too large")
				return
			}
			file = bytes.NewReader(fileBytes)
		}

		if file == nil {
			writeJSONError(w, http.StatusBadRequest, "missing avatar file")
			return
		}

		imgConfig, _, err := image.DecodeConfig(file)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid image format")
			return
		}

		// Restrict to reasonable max dimensions (prevent decompression bombs)
		if imgConfig.Width > 4000 || imgConfig.Height > 4000 {
			writeJSONError(w, http.StatusBadRequest, "image dimensions too large")
			return
		}

		if _, err = file.Seek(0, io.SeekStart); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "invalid file")
			return
		}

		img, _, err := image.Decode(file)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "unsupported file type")
			return
		}

		var buf bytes.Buffer
		if err = jpeg.Encode(&buf, resizePicture(img), &jpeg.Options{Quality: 90}); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to encode image")
			return
		}

		avatarPath := storage.AvatarPath(user.ID)
		fileURL, err := cfg.Storage.Store(
			r.Context(),
			avatarPath,
			buf.Bytes(),
			storage.StoreOptions{
				ContentType:  "image/jpeg",
				CacheControl: "public, max-age=864000, immutable",
			},
		)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to upload picture")
			return
		}

		versionedURL := fmt.Sprintf("%s?v=%d", *fileURL, time.Now().UnixMilli())

		if _, err := cfg.Conn.Q.UpdateUser(r.Context(), &db.UpdateUserParams{
			UserID:  userID,
			Picture: &versionedURL,
		}); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Failed to update picture")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func ServeAvatar(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Strip extension from /avatars/{id}
		userID, _, ok := strings.Cut(r.PathValue("id"), ".")
		if userID == "" || !ok {
			writeJSONError(w, http.StatusBadRequest, "missing user ID")
			return
		}

		avatarPath := storage.AvatarPath(userID)
		if url, ok := cfg.Storage.PublicURL(avatarPath); ok {
			http.Redirect(w, r, url, http.StatusFound) // #nosec G710 -- host is the fixed CDNURL
			return
		}

		rc, err := cfg.Storage.Reader(r.Context(), avatarPath)
		if err != nil {
			writeJSONError(w, http.StatusNotFound, "file not found")
			return
		}
		defer func() { _ = rc.Close() }()

		w.Header().Set("Content-Type", "image/jpeg")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		if _, err = io.Copy(w, rc); err != nil { // #nosec G705
			slog.Error("failed to write avatar", "error", err)
		}
	}
}
