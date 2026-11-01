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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gocloud.dev/gcerrors"
)

func newLocal(t *testing.T) *Storage {
	t.Helper()
	t.Setenv("NOKKU_STORAGE_URL", "file://"+filepath.Join(t.TempDir(), "data"))
	s, err := New(t.Context())
	require.NoError(t, err)
	return s
}

// A local directory is created. Temp files stay in it, renames cross no volume.
func TestBucketURL(t *testing.T) {
	for in, want := range map[string]string{
		"file://./data":                 "file://./data?create_dir=true&dir_file_mode=0750&no_tmp_dir=true",
		"file:///srv/nokku?create_dir=": "file:///srv/nokku?create_dir=&dir_file_mode=0750&no_tmp_dir=true",
		"s3://rec?region=eu&endpoint=x": "s3://rec?region=eu&endpoint=x",
		"file:///d?dir_file_mode=0700":  "file:///d?create_dir=true&dir_file_mode=0700&no_tmp_dir=true",
	} {
		got, err := bucketURL(in)
		if assert.NoError(t, err, "bucketURL(%q)", in) {
			assert.Equal(t, want, got, "bucketURL(%q)", in)
		}
	}
}

func TestNewCreatesTheDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "not", "there")
	t.Setenv("NOKKU_STORAGE_URL", "file://"+dir)
	_, err := New(t.Context())
	require.NoError(t, err)
	require.DirExists(t, dir)
}

func TestNewRefusesAnUnknownScheme(t *testing.T) {
	t.Setenv("NOKKU_STORAGE_URL", "ftp://example.com/x")
	_, err := New(t.Context())
	require.Error(t, err, "an unknown scheme was accepted")
}

// fileblob escapes separators and "..", so nothing lands outside the bucket.
func TestCreateWriterConfinesTraversalNames(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")
	t.Setenv("NOKKU_STORAGE_URL", "file://"+root)
	s, err := New(t.Context())
	require.NoError(t, err)
	for _, name := range []string{"../evil", "a/../../evil", "/etc/passwd"} {
		w, err := s.CreateWriter(t.Context(), name)
		require.NoError(t, err, name)
		_, err = w.Write([]byte("x"))
		require.NoError(t, err, name)
		require.NoError(t, w.Close(), name)
	}
	err = filepath.WalkDir(filepath.Dir(root), func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			assert.True(t, strings.HasPrefix(p, root+string(filepath.Separator)), "object escaped bucket root: %q", p)
		}
		return nil
	})
	require.NoError(t, err)
}

func TestCreateWriterEmptyName(t *testing.T) {
	_, err := newLocal(t).CreateWriter(t.Context(), "")
	assert.Error(t, err, "CreateWriter with an empty name")
}

func TestReaderMissingObject(t *testing.T) {
	_, err := newLocal(t).Reader(t.Context(), "nope/missing.bin")
	assert.Equal(t, gcerrors.NotFound, gcerrors.Code(err), "Reader(missing): %v", err)
}

func useBucketAt(t *testing.T, endpoint string) {
	t.Helper()
	t.Setenv("NOKKU_STORAGE_URL", "s3://rec?region=auto&use_path_style=true&endpoint="+url.QueryEscape(endpoint))
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	probeTimeout = 200 * time.Millisecond
	t.Cleanup(func() { probeTimeout = 5 * time.Second })
}

// A bucket that connects and then says nothing must not hold up the start.
func TestNewDoesNotWaitForABucketThatHangs(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
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
	_, err = New(t.Context())
	require.NoError(t, err, "a bucket that hangs stopped the start")
	assert.LessOrEqual(t, time.Since(start), 2*time.Second, "the check waited out the bucket")
}

// A bucket outage must not refuse logins, daemons keep recordings until it
// ends.
func TestNewStartsWithABucketThatIsDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	_ = ln.Close()
	useBucketAt(t, "http://"+addr)

	_, err = New(t.Context())
	require.NoError(t, err, "a bucket that is down stopped the start")
}

// A bucket's no is a wrong setting and stops the start. An outage does not.
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
			if starts {
				assert.NoError(t, err, "an outage stopped the start")
				return
			}
			assert.ErrorContains(t, err, "storage refused the core", "a wrong setting let the core start")
		})
	}
}

func TestNewRefusesAFolderItCannotRead(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads every folder")
	}
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	t.Setenv("NOKKU_STORAGE_URL", "file://"+dir)

	_, err := New(t.Context())
	require.Error(t, err, "a folder the core can't read let it start")
}
