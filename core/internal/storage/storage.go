// Package storage keeps the recordings, in a local directory or an S3 bucket, opened from one URL.
package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/caarlos0/env/v11"
	"gocloud.dev/blob"
	_ "gocloud.dev/blob/fileblob" // file:// URLs
	_ "gocloud.dev/blob/s3blob"   // s3:// URLs
	"gocloud.dev/gcerrors"
)

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
	// Fail on boot, not on the first upload.
	if _, err := bucket.Attributes(ctx, ".nokku-probe"); err != nil && gcerrors.Code(err) != gcerrors.NotFound {
		_ = bucket.Close()
		return nil, fmt.Errorf("storage unreachable: %w", err)
	}
	context.AfterFunc(ctx, func() { _ = bucket.Close() })
	return &Storage{bucket: bucket}, nil
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

// DeletePrefix only takes directory prefixes, so "videos/a" can never match "videos/ab".
func (s *Storage) DeletePrefix(ctx context.Context, prefix string) error {
	if !strings.HasSuffix(prefix, "/") || strings.Trim(prefix, "/") == "" {
		return fmt.Errorf("refusing to delete prefix %q", prefix)
	}
	var errs []error
	iter := s.bucket.List(&blob.ListOptions{Prefix: prefix})
	for {
		obj, err := iter.Next(ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if err := s.Delete(ctx, obj.Key); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// CreateWriter commits on Close, so a truncated upload leaves a partial object. Canceling ctx drops it.
func (s *Storage) CreateWriter(ctx context.Context, name string) (io.WriteCloser, error) {
	if name == "" {
		return nil, errors.New("filename is empty")
	}
	w, err := s.bucket.NewWriter(ctx, name, &blob.WriterOptions{ContentType: "application/octet-stream"})
	if err != nil {
		return nil, fmt.Errorf("open writer for %q: %w", name, err)
	}
	return w, nil
}
