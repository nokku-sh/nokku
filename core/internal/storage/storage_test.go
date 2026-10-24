package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gocloud.dev/gcerrors"
)

func newLocal(t *testing.T) *Storage {
	t.Helper()
	t.Setenv("NOKKU_STORAGE_URL", "file://"+filepath.Join(t.TempDir(), "data"))
	s, err := New(t.Context())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func write(t *testing.T, s *Storage, key string) {
	t.Helper()
	w, err := s.CreateWriter(t.Context(), key)
	if err != nil {
		t.Fatalf("CreateWriter %s: %v", key, err)
	}
	if _, err := w.Write([]byte("x")); err != nil {
		t.Fatalf("write %s: %v", key, err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close %s: %v", key, err)
	}
}

// A local directory is created, and its temp files stay in it so a rename never crosses volumes.
func TestBucketURL(t *testing.T) {
	for in, want := range map[string]string{
		"file://./data":                 "file://./data?create_dir=true&dir_file_mode=0750&no_tmp_dir=true",
		"file:///srv/nokku?create_dir=": "file:///srv/nokku?create_dir=&dir_file_mode=0750&no_tmp_dir=true",
		"s3://rec?region=eu&endpoint=x": "s3://rec?region=eu&endpoint=x",
		"file:///d?dir_file_mode=0700":  "file:///d?create_dir=true&dir_file_mode=0700&no_tmp_dir=true",
	} {
		got, err := bucketURL(in)
		if err != nil || got != want {
			t.Errorf("bucketURL(%q) = %q, %v, want %q", in, got, err, want)
		}
	}
}

func TestNewCreatesTheDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "not", "there")
	t.Setenv("NOKKU_STORAGE_URL", "file://"+dir)
	if _, err := New(t.Context()); err != nil {
		t.Fatalf("New: %v", err)
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Fatalf("the directory was not created: %v", err)
	}
}

func TestNewRefusesAnUnknownScheme(t *testing.T) {
	t.Setenv("NOKKU_STORAGE_URL", "ftp://example.com/x")
	if _, err := New(t.Context()); err == nil {
		t.Fatal("an unknown scheme was accepted")
	}
}

// fileblob escapes path separators and ".." in object names, nothing may land outside the bucket root.
func TestCreateWriterConfinesTraversalNames(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")
	t.Setenv("NOKKU_STORAGE_URL", "file://"+root)
	s, err := New(t.Context())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, name := range []string{"../evil", "a/../../evil", "/etc/passwd"} {
		write(t, s, name)
	}
	err = filepath.WalkDir(filepath.Dir(root), func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && !strings.HasPrefix(p, root+string(filepath.Separator)) {
			t.Errorf("object escaped bucket root: %q", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateWriterEmptyName(t *testing.T) {
	if _, err := newLocal(t).CreateWriter(t.Context(), ""); err == nil {
		t.Error("CreateWriter with an empty name: expected error")
	}
}

func TestReaderMissingObject(t *testing.T) {
	_, err := newLocal(t).Reader(t.Context(), "nope/missing.bin")
	if err == nil || gcerrors.Code(err) != gcerrors.NotFound {
		t.Errorf("Reader(missing) error = %v, want NotFound", err)
	}
}
