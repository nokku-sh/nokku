package storage

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalStorage(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NOKKU_LOCAL_STORAGE_PATH", dir)

	s, err := New(t.Context(), "http://localhost:3000")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.Mode != modeLocal {
		t.Fatalf("expected local mode, got %q", s.Mode)
	}
	if _, ok := s.PublicURL("avatars/x.jpg"); ok {
		t.Fatal("PublicURL should be false for local storage")
	}

	path := AvatarPath("user-1")
	url, err := s.Store(t.Context(), path, []byte("avatar-data"), StoreOptions{
		ContentType:  "image/jpeg",
		CacheControl: "public, max-age=31536000, immutable",
	})
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	if url != "http://localhost:3000/"+path {
		t.Fatalf("unexpected url %q", url)
	}
	if _, err := os.Stat(filepath.Join(dir, path)); err != nil {
		t.Fatalf("file not written to disk: %v", err)
	}

	rc, err := s.Reader(t.Context(), path)
	if err != nil {
		t.Fatalf("Reader: %v", err)
	}
	data, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(data) != "avatar-data" {
		t.Fatalf("unexpected data %q", data)
	}

	if err := s.Delete(t.Context(), path); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := s.Delete(t.Context(), path); err != nil {
		t.Fatalf("Delete of missing object should be a no-op: %v", err)
	}
	if err := s.bucket.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestNewInvalidMode(t *testing.T) {
	t.Setenv("NOKKU_STORAGE", "garbage")
	if _, err := New(t.Context(), "http://localhost:3000"); err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestNewS3RequiresConfig(t *testing.T) {
	t.Setenv("NOKKU_STORAGE", "s3")
	t.Setenv("NOKKU_S3_ENDPOINT", "")
	if _, err := New(t.Context(), "http://localhost:3000"); err == nil {
		t.Fatal("expected error for s3 mode without endpoint")
	}
}

func TestJoinURL(t *testing.T) {
	for _, tc := range []struct{ base, name, want string }{
		{"https://cdn.example.com", "avatars/a.jpg", "https://cdn.example.com/avatars/a.jpg"},
		{"https://cdn.example.com/", "avatars/a.jpg", "https://cdn.example.com/avatars/a.jpg"},
		{"", "avatars/a.jpg", "avatars/a.jpg"},
	} {
		if got := joinURL(tc.base, tc.name); got != tc.want {
			t.Errorf("joinURL(%q, %q) = %q, want %q", tc.base, tc.name, got, tc.want)
		}
	}
}
