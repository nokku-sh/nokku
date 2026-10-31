// Package storage keeps the recordings, in a local directory or an S3 bucket, opened from one URL.
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
	"time"

	"github.com/caarlos0/env/v11"
	"gocloud.dev/blob"
	_ "gocloud.dev/blob/fileblob" // file:// URLs
	_ "gocloud.dev/blob/s3blob"   // s3:// URLs
	"gocloud.dev/gcerrors"
)

// probeTimeout bounds the check at boot, a bucket that hangs must not hold up the start. Tests shorten it.
var probeTimeout = 5 * time.Second

type Storage struct {
	bucket *blob.Bucket
}

type config struct {
	// URL is file:///dir, or s3://bucket?region=...&endpoint=...&use_path_style=true with credentials in AWS_*.
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
		// Maybe a passing outage. Daemons keep their recordings until it ends, and logins don't need storage.
		slog.Warn("storage unreachable, recordings wait on the daemons until it is back", "error", err)
	}
	context.AfterFunc(ctx, func() { _ = bucket.Close() })
	return &Storage{bucket: bucket}, nil
}

// refused is storage that answered and said no, a wrong setting fails on boot and not on the first upload.
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
	// 0 is a request that got no answer. A 5xx or a 429 is the bucket having trouble, not a verdict.
	status := answer.HTTPStatusCode()
	return status > 0 && status < http.StatusInternalServerError && status != http.StatusTooManyRequests
}

// bucketURL creates a missing directory and keeps its temp files inside it, a rename across volumes fails in a
// container. A URL that says otherwise wins.
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

// CreateWriter commits on Close, so a truncated upload leaves a partial object. Canceling ctx drops it.
func (s *Storage) CreateWriter(ctx context.Context, name string) (io.WriteCloser, error) {
	if name == "" {
		return nil, errors.New("filename is empty")
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
	return w, nil
}
