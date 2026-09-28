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
	"strings"
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
	Bucket          string `env:"NOKKU_S3_BUCKET"            envDefault:"nokku-assets"`
	Region          string `env:"NOKKU_S3_REGION"            envDefault:"auto"`
	UsePathStyle    bool   `env:"NOKKU_S3_USE_PATH_STYLE"    envDefault:"false"`
	CDNURL          string `env:"NOKKU_S3_PUBLIC_URL"`
	LocalPath       string `env:"NOKKU_LOCAL_STORAGE_PATH"   envDefault:"data"`
	BaseURL         string

	bucket *blob.Bucket
}

func New(ctx context.Context, baseURL string) (*Storage, error) {
	s, err := env.ParseAs[Storage]()
	if err != nil {
		return nil, err
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

	// Fail on boot, not on the first upload.
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
) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	writerOpts := &blob.WriterOptions{
		ContentType:  opts.ContentType,
		CacheControl: opts.CacheControl,
	}
	if err := s.bucket.WriteAll(ctx, name, data, writerOpts); err != nil {
		return "", fmt.Errorf("write data: %w", err)
	}
	return s.getURL(name), nil
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

// DeletePrefix only takes directory prefixes, so "videos/a" can never match
// "videos/ab".
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

// CreateWriter commits on Close, so a truncated upload leaves a partial object.
func (s *Storage) CreateWriter(
	ctx context.Context,
	name string,
	opts StoreOptions,
) (io.WriteCloser, error) {
	if name == "" {
		return nil, errors.New("filename is empty")
	}
	w, err := s.bucket.NewWriter(ctx, name, &blob.WriterOptions{
		ContentType:  opts.ContentType,
		CacheControl: opts.CacheControl,
	})
	if err != nil {
		return nil, fmt.Errorf("open writer for %q: %w", name, err)
	}
	return w, nil
}

// PublicURL is false for local storage, which the server proxies.
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
	return joinURL(s.BaseURL, name)
}

func joinURL(base, name string) string {
	u, err := url.JoinPath(base, name)
	if err != nil {
		return base + "/" + name
	}
	return u
}
