// Package storage keeps recordings in a local directory or an S3 bucket.
package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/caarlos0/env/v11"
	"gocloud.dev/blob"
	_ "gocloud.dev/blob/fileblob" // file:// URLs
	_ "gocloud.dev/blob/s3blob"   // s3:// URLs
	"gocloud.dev/gcerrors"
)

// roomCheckEvery is how much one recording writes between two looks at the disk.
const roomCheckEvery = 1 << 20

// A bucket that hangs must not hold up the start. Tests shorten it.
var probeTimeout = 5 * time.Second

// minFreeDisk is what a folder leaves free. It often shares its disk with PostgreSQL, which stops when that is
// full. Tests raise it.
var minFreeDisk uint64 = 1 << 30

// ErrFull means the folder's disk is nearly full. The daemon keeps its recording and sends it later.
var ErrFull = errors.New("storage: the disk of the recordings folder is nearly full")

type Storage struct {
	bucket *blob.Bucket
	// dir is the folder of a file:// URL. A bucket has no disk of ours to fill.
	dir string
}

// roomWriter stops a recording that is being written once the disk is nearly full.
type roomWriter struct {
	io.WriteCloser

	store   *Storage
	written int
}

type config struct {
	// URL is file:///dir or s3://bucket?region=..., credentials in AWS_*.
	URL string `env:"NOKKU_STORAGE_URL" envDefault:"file://./data"`
}

func New(ctx context.Context) (*Storage, error) {
	cfg, err := env.ParseAs[config]()
	if err != nil {
		return nil, err
	}
	u, err := bucketURL(cfg.URL)
	if err != nil {
		return nil, err
	}
	bucket, err := blob.OpenBucket(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("open NOKKU_STORAGE_URL: %w", err)
	}
	probe, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	_, err = bucket.Attributes(probe, ".nokku-probe")
	switch {
	case err == nil, gcerrors.Code(err) == gcerrors.NotFound:
	case refused(err):
		_ = bucket.Close()
		return nil, fmt.Errorf("storage refused the core: %w", err)
	default:
		// Maybe an outage. Daemons hold recordings, logins don't need storage.
		slog.Warn("storage unreachable, recordings wait on the daemons until it is back", "error", err)
	}
	context.AfterFunc(ctx, func() { _ = bucket.Close() })
	s := &Storage{bucket: bucket}
	// The same reading of the URL as gocloud's fileblob.
	if parsed, _ := url.Parse(u); parsed != nil && parsed.Scheme == "file" {
		s.dir = parsed.Path
		if parsed.Host == "." {
			s.dir = strings.TrimPrefix(s.dir, "/")
		}
	}
	return s, nil
}

// HasRoom is false for a folder whose disk is nearly full. A disk that cannot be read counts as having room.
func (s *Storage) HasRoom() bool {
	if s.dir == "" {
		return true
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(s.dir, &st); err != nil || st.Bsize <= 0 {
		slog.Warn("free space of the recordings folder unknown", "dir", s.dir, "error", err)
		return true
	}
	return st.Bavail*uint64(st.Bsize) >= minFreeDisk
}

func (w *roomWriter) Write(p []byte) (int, error) {
	before := w.written / roomCheckEvery
	w.written += len(p)
	if w.written/roomCheckEvery != before && !w.store.HasRoom() {
		return 0, ErrFull
	}
	return w.WriteCloser.Write(p)
}

// refused is storage saying no, so a wrong setting fails at boot.
func refused(err error) bool {
	if errors.Is(err, fs.ErrPermission) {
		return true
	}
	answer, ok := errors.AsType[interface {
		error
		HTTPStatusCode() int
	}](err)
	if !ok {
		return false
	}
	// 0 got no answer. A 5xx or a 429 is the bucket's trouble, not a verdict.
	status := answer.HTTPStatusCode()
	return status > 0 && status < http.StatusInternalServerError && status != http.StatusTooManyRequests
}

// Keeps temp files in the dir, a rename across volumes fails in a container.
func bucketURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("NOKKU_STORAGE_URL: %w", err)
	}
	if u.Scheme != "file" {
		return raw, nil
	}
	q := u.Query()
	for key, value := range map[string]string{"create_dir": "true", "no_tmp_dir": "true", "dir_file_mode": "0750"} {
		if !q.Has(key) {
			q.Set(key, value)
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (s *Storage) Reader(ctx context.Context, name string) (io.ReadCloser, error) {
	reader, err := s.bucket.NewReader(ctx, name, nil)
	if err != nil {
		return nil, fmt.Errorf("open reader: %w", err)
	}
	return reader, nil
}

func (s *Storage) Delete(ctx context.Context, name string) error {
	if name == "" {
		return errors.New("filename is empty")
	}
	err := s.bucket.Delete(ctx, name)
	if gcerrors.Code(err) == gcerrors.NotFound {
		return nil
	}
	if err != nil {
		return fmt.Errorf("delete object: %w", err)
	}
	return nil
}

// CreateWriter commits on Close, even when truncated. Canceling ctx drops it.
func (s *Storage) CreateWriter(ctx context.Context, name string) (io.WriteCloser, error) {
	if name == "" {
		return nil, errors.New("filename is empty")
	}
	if !s.HasRoom() {
		return nil, ErrFull
	}
	// The smallest part S3 takes, one at a time. The SDK's defaults hold 48 MiB
	// per upload, and a live session keeps its upload open for hours.
	w, err := s.bucket.NewWriter(ctx, name, &blob.WriterOptions{
		ContentType:    "application/octet-stream",
		BufferSize:     5 << 20,
		MaxConcurrency: 1,
	})
	if err != nil {
		return nil, fmt.Errorf("open writer for %q: %w", name, err)
	}
	return &roomWriter{WriteCloser: w, store: s}, nil
}
