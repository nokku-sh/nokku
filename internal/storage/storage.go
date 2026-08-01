package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/caarlos0/env/v11"
	"gocloud.dev/blob"
	"gocloud.dev/blob/fileblob"
	"gocloud.dev/blob/s3blob"
	"gocloud.dev/gcerrors"
)

const (
	ModeLocal = "local"
	ModeS3    = "s3"
)

type Storage struct {
	Mode            string `env:"NOKKU_STORAGE"              envDefault:"local"`
	Endpoint        string `env:"NOKKU_S3_ENDPOINT"`
	AccessKeyID     string `env:"NOKKU_S3_ACCESS_KEY_ID"`
	SecretAccessKey string `env:"NOKKU_S3_SECRET_ACCESS_KEY"`
	Bucket          string `env:"NOKKU_S3_BUCKET"            envDefault:"cdn"`
	Region          string `env:"NOKKU_S3_REGION"            envDefault:"auto"`
	UsePathStyle    bool   `env:"NOKKU_S3_USE_PATH_STYLE"    envDefault:"false"`
	CDNURL          string `env:"NOKKU_S3_PUBLIC_URL"`
	LocalPath       string `env:"NOKKU_LOCAL_STORAGE_PATH"   envDefault:"data"`
	BaseURL         string

	bucket *blob.Bucket
}

// New creates a storage backend. The backend is selected explicitly:
//   - NOKKU_STORAGE=s3 - S3-compatible object storage (Scaleway, R2, MinIO, AWS)
//   - NOKKU_STORAGE=local (default) - local filesystem at NOKKU_LOCAL_STORAGE_PATH
func New(ctx context.Context, baseURL string) (*Storage, error) {
	var s Storage
	if err := env.Parse(&s); err != nil {
		return nil, fmt.Errorf("parse storage config: %w", err)
	}
	s.BaseURL = baseURL

	switch s.Mode {
	case ModeS3:
		if err := s.initS3(ctx); err != nil {
			return nil, err
		}
	case ModeLocal:
		if err := s.initLocal(); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf(
			"invalid NOKKU_STORAGE mode %q (must be %q or %q)",
			s.Mode,
			ModeLocal,
			ModeS3,
		)
	}

	// Handle shutdown
	go func() {
		<-ctx.Done()
		if s.bucket != nil {
			_ = s.bucket.Close()
		}
	}()
	return &s, nil
}

func (s *Storage) initS3(ctx context.Context) error {
	if s.Endpoint == "" {
		return errors.New("NOKKU_S3_ENDPOINT is required in s3 mode")
	}
	if s.AccessKeyID == "" || s.SecretAccessKey == "" {
		return errors.New(
			"NOKKU_S3_ACCESS_KEY_ID and NOKKU_S3_SECRET_ACCESS_KEY are required in s3 mode",
		)
	}
	if s.Bucket == "" {
		return errors.New("NOKKU_S3_BUCKET is required in s3 mode")
	}

	awsCfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithRegion(s.Region),
		config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(s.AccessKeyID, s.SecretAccessKey, ""),
		),
	)
	if err != nil {
		return fmt.Errorf("load aws config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(s.Endpoint)
		o.UsePathStyle = s.UsePathStyle
	})

	s.bucket, err = s3blob.OpenBucket(ctx, client, s.Bucket, nil)
	if err != nil {
		return fmt.Errorf("open s3 bucket: %w", err)
	}

	// Fail fast: verify credentials and bucket access at startup so a
	// misconfigured deployment surfaces on boot, not on the first upload.
	if _, err := s.bucket.Attributes(ctx, ".nokku-probe"); err != nil {
		if code := gcerrors.Code(err); code != gcerrors.NotFound {
			_ = s.bucket.Close()
			return fmt.Errorf("s3 bucket unreachable: %w", err)
		}
	}

	slog.Debug("using s3 bucket", "bucket", s.Bucket, "endpoint", s.Endpoint, "region", s.Region)
	return nil
}

func (s *Storage) initLocal() error {
	if err := os.MkdirAll(s.LocalPath, 0o750); err != nil {
		return fmt.Errorf("create local storage path: %w", err)
	}
	absPath, err := filepath.Abs(s.LocalPath)
	if err != nil {
		return fmt.Errorf("get absolute path: %w", err)
	}

	s.bucket, err = fileblob.OpenBucket(absPath, &fileblob.Options{NoTempDir: true})
	if err != nil {
		return fmt.Errorf("open local bucket: %w", err)
	}

	slog.Debug("using local filesystem", "path", absPath)
	return nil
}

func (s *Storage) Reader(ctx context.Context, name string) (io.ReadCloser, error) {
	reader, err := s.bucket.NewReader(ctx, name, nil)
	if err != nil {
		return nil, fmt.Errorf("open reader: %w", err)
	}
	return reader, nil
}

func (s *Storage) Store(
	ctx context.Context,
	name string,
	data []byte,
	opts StoreOptions,
) (*string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	writerOpts := &blob.WriterOptions{
		ContentType:  opts.ContentType,
		CacheControl: opts.CacheControl,
		Metadata:     opts.Metadata,
	}
	if err := s.bucket.WriteAll(ctx, name, data, writerOpts); err != nil {
		return nil, fmt.Errorf("write data: %w", err)
	}
	url := s.getURL(name)
	return &url, nil
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

func (s *Storage) Exists(ctx context.Context, name string) (bool, error) {
	_, err := s.bucket.Attributes(ctx, name)
	if err != nil {
		if gcerrors.Code(err) == gcerrors.NotFound {
			return false, nil
		}
		return false, fmt.Errorf("check existence: %w", err)
	}
	return true, nil
}

// PublicURL returns the public URL for name when the backend serves objects
// directly (S3 + PublicURL) and false otherwise (local storage is proxied
// through the application server).
func (s *Storage) PublicURL(name string) (string, bool) {
	if s.CDNURL == "" {
		return "", false
	}
	return s.getURL(name), true
}

func (s *Storage) getURL(name string) string {
	if s.CDNURL != "" {
		return joinURL(s.CDNURL, name)
	}
	if s.BaseURL != "" {
		return joinURL(s.BaseURL, name)
	}
	return name
}

func joinURL(base, name string) string {
	u, err := url.JoinPath(base, name)
	if err != nil {
		return base + "/" + name
	}
	return u
}
