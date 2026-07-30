package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
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

type Storage struct {
	Endpoint        string `env:"NOKKU_S3_ENDPOINT"`
	AccessKeyID     string `env:"NOKKU_S3_ACCESS_KEY_ID"`
	SecretAccessKey string `env:"NOKKU_S3_SECRET_ACCESS_KEY"`
	Bucket          string `env:"NOKKU_S3_BUCKET"            envDefault:"cdn"`
	Region          string `env:"NOKKU_S3_REGION"            envDefault:"auto"`
	UsePathStyle    bool   `env:"NOKKU_S3_USE_PATH_STYLE"    envDefault:"false"`
	PublicURL       string `env:"NOKKU_S3_PUBLIC_URL"`
	LocalPath       string `env:"NOKKU_LOCAL_STORAGE_PATH"   envDefault:"data"`
	BaseURL         string

	bucket *blob.Bucket
}

// New creates a storage backend.
//   - If NOKKU_S3_ACCESS_KEY_ID and NOKKU_S3_SECRET_ACCESS_KEY are set → S3-compatible (R2, MinIO, AWS)
//   - Otherwise → local filesystem at NOKKU_LOCAL_STORAGE_PATH
func New(ctx context.Context, baseURL string) (*Storage, error) {
	var s Storage
	if err := env.Parse(&s); err != nil {
		return nil, fmt.Errorf("parse storage config: %w", err)
	}
	s.BaseURL = baseURL

	if s.isS3() {
		if err := s.initS3(ctx); err != nil {
			return nil, err
		}
	} else {
		if err := s.initLocal(); err != nil {
			return nil, err
		}
	}

	return &s, nil
}

func (s *Storage) isS3() bool {
	return s.AccessKeyID != "" && s.SecretAccessKey != ""
}

func (s *Storage) initS3(ctx context.Context) error {
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
		if s.Endpoint != "" {
			o.BaseEndpoint = aws.String(s.Endpoint)
		}
		o.UsePathStyle = s.UsePathStyle
	})

	s.bucket, err = s3blob.OpenBucket(ctx, client, s.Bucket, nil)
	if err != nil {
		return fmt.Errorf("open s3 bucket: %w", err)
	}

	slog.Debug("Using S3 bucket", "bucket", s.Bucket, "endpoint", s.Endpoint)
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

	slog.Debug("Using local filesystem", "path", absPath)
	return nil
}

func (s *Storage) Get(ctx context.Context, name string) (*FileInfo, error) {
	attrs, err := s.bucket.Attributes(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("get attributes: %w", err)
	}

	return &FileInfo{
		Name:         name,
		URL:          s.getURL(name),
		Size:         attrs.Size,
		ContentType:  attrs.ContentType,
		LastModified: attrs.ModTime,
		Metadata:     attrs.Metadata,
	}, nil
}

func (s *Storage) Read(ctx context.Context, name string) ([]byte, error) {
	r, err := s.Reader(ctx, name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read data: %w", err)
	}
	return data, nil
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

func (s *Storage) List(ctx context.Context, prefix string) ([]string, error) {
	var files []string
	iter := s.bucket.List(&blob.ListOptions{Prefix: prefix})

	for {
		obj, err := iter.Next(ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list objects: %w", err)
		}
		if !obj.IsDir {
			files = append(files, obj.Key)
		}
	}

	return files, nil
}

func (s *Storage) Delete(ctx context.Context, name string) error {
	if name == "" {
		return fmt.Errorf("filename is empty")
	}
	return s.bucket.Delete(ctx, name)
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

func (s *Storage) getURL(name string) string {
	if s.PublicURL != "" {
		return fmt.Sprintf("%s/%s", s.PublicURL, name)
	}
	if s.BaseURL != "" {
		return fmt.Sprintf("%s/%s", s.BaseURL, name)
	}
	return name
}
