package storage

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func useBucketAt(t *testing.T, endpoint string) {
	t.Helper()
	t.Setenv("NOKKU_STORAGE_URL", "s3://rec?region=auto&use_path_style=true&endpoint="+url.QueryEscape(endpoint))
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	probeTimeout = 200 * time.Millisecond
	t.Cleanup(func() { probeTimeout = 5 * time.Second })
}

// A bucket that takes the connection and then says nothing must not hold up the start.
func TestNewDoesNotWaitForABucketThatHangs(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()
	useBucketAt(t, "http://"+ln.Addr().String())

	start := time.Now()
	if _, err := New(t.Context()); err != nil {
		t.Fatalf("a bucket that hangs stopped the start: %v", err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("the check waited out the bucket, %s", took)
	}
}

// An outage of the bucket is no reason to refuse logins, daemons keep their recordings until it ends.
func TestNewStartsWithABucketThatIsDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	useBucketAt(t, "http://"+addr)

	if _, err := New(t.Context()); err != nil {
		t.Fatalf("a bucket that is down stopped the start: %v", err)
	}
}

// A bucket that says no is a wrong setting and stops the start. One having trouble is an outage and does not.
func TestNewSortsWhatTheBucketAnswers(t *testing.T) {
	for status, starts := range map[int]bool{
		http.StatusBadRequest:          false,
		http.StatusUnauthorized:        false,
		http.StatusForbidden:           false,
		http.StatusTooManyRequests:     true,
		http.StatusInternalServerError: true,
		http.StatusServiceUnavailable:  true,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			}))
			t.Cleanup(srv.Close)
			useBucketAt(t, srv.URL)

			_, err := New(t.Context())
			if starts && err != nil {
				t.Errorf("an outage stopped the start: %v", err)
			}
			if !starts && (err == nil || !strings.Contains(err.Error(), "storage refused the core")) {
				t.Errorf("a wrong setting let the core start, err = %v", err)
			}
		})
	}
}

func TestNewRefusesAFolderItCannotRead(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads every folder")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	t.Setenv("NOKKU_STORAGE_URL", "file://"+dir)

	if _, err := New(t.Context()); err == nil {
		t.Fatal("a folder the core can't read let it start")
	}
}
