package storage

import (
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"gocloud.dev/gcerrors"
)

func newLocal(t *testing.T) *Storage {
	t.Helper()
	t.Setenv("NOKKU_LOCAL_STORAGE_PATH", filepath.Join(t.TempDir(), "data"))
	s, err := New(t.Context(), "http://localhost:3000")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestAvatarPath(t *testing.T) {
	got := AvatarPath("user-1")
	if !strings.HasPrefix(got, pathAvatars+"/") || !strings.HasSuffix(got, ".jpg") {
		t.Errorf("AvatarPath = %q, want under %q with .jpg suffix", got, pathAvatars)
	}
	if path.Clean(got) != got {
		t.Errorf("AvatarPath %q is not clean", got)
	}
}

func TestStore_ConfinesTraversalNames(t *testing.T) {
	s := newLocal(t)
	root, err := filepath.Abs(s.LocalPath)
	if err != nil {
		t.Fatal(err)
	}

	// fileblob escapes path separators and ".." in object names, nothing may land outside the bucket root.
	for _, name := range []string{"../evil", "a/../../evil", "/etc/passwd"} {
		if _, err := s.Store(t.Context(), name, []byte("x"), StoreOptions{}); err != nil {
			t.Fatalf("Store(%q): %v", name, err)
		}
	}

	err = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasPrefix(p, root+string(filepath.Separator)) {
			t.Errorf("object escaped bucket root: %q", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// The parent of the bucket root must stay empty.
	parent := filepath.Dir(root)
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("parent dir has unexpected entries: %v", entries)
	}
}

func TestStore_EmptyName(t *testing.T) {
	s := newLocal(t)
	if _, err := s.Store(t.Context(), "", []byte("x"), StoreOptions{}); err == nil {
		t.Error("Store with empty name: expected error")
	}
}

func TestStore_PersistsContentType(t *testing.T) {
	s := newLocal(t)

	name := "avatars/a.jpg"
	if _, err := s.Store(t.Context(), name, []byte("data"), StoreOptions{
		ContentType:  "image/jpeg",
		CacheControl: "public, max-age=31536000",
	}); err != nil {
		t.Fatalf("Store: %v", err)
	}

	attrs, err := s.bucket.Attributes(t.Context(), name)
	if err != nil {
		t.Fatalf("Attributes: %v", err)
	}
	if attrs.ContentType != "image/jpeg" {
		t.Errorf("ContentType = %q, want image/jpeg", attrs.ContentType)
	}
	if attrs.CacheControl != "public, max-age=31536000" {
		t.Errorf("CacheControl = %q, want set", attrs.CacheControl)
	}
}

func TestReader_MissingObject(t *testing.T) {
	s := newLocal(t)
	_, err := s.Reader(t.Context(), "nope/missing.bin")
	if err == nil || gcerrors.Code(err) != gcerrors.NotFound {
		t.Errorf("Reader(missing) error = %v, want NotFound", err)
	}
}

func TestGetURL_Precedence(t *testing.T) {
	s := &Storage{CDNURL: "https://cdn.example.com", BaseURL: "https://app.example.com"}
	if got := s.getURL("avatars/a.jpg"); got != "https://cdn.example.com/avatars/a.jpg" {
		t.Errorf("CDNURL precedence: got %q", got)
	}

	s = &Storage{BaseURL: "https://app.example.com"}
	if got := s.getURL("avatars/a.jpg"); got != "https://app.example.com/avatars/a.jpg" {
		t.Errorf("BaseURL fallback: got %q", got)
	}

	s = &Storage{}
	if got := s.getURL("avatars/a.jpg"); got != "avatars/a.jpg" {
		t.Errorf("bare name fallback: got %q", got)
	}
}

func TestPublicURL(t *testing.T) {
	s := &Storage{CDNURL: "https://cdn.example.com"}
	url, ok := s.PublicURL("avatars/a.jpg")
	if !ok || url != "https://cdn.example.com/avatars/a.jpg" {
		t.Errorf("PublicURL = %q, %v", url, ok)
	}

	s = &Storage{}
	if _, ok := s.PublicURL("avatars/a.jpg"); ok {
		t.Error("PublicURL should be false without CDNURL")
	}
}
