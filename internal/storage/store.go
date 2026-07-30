package storage

import (
	"context"
	"io"
	"path"
	"time"
)

const (
	PathAvatars = "avatars"
)

type Store interface {
	Get(ctx context.Context, name string) (*FileInfo, error)
	Read(ctx context.Context, name string) ([]byte, error)
	Reader(ctx context.Context, name string) (io.ReadCloser, error)
	Store(ctx context.Context, name string, data []byte, opts StoreOptions) (*string, error)
	Delete(ctx context.Context, name string) error
	List(ctx context.Context, prefix string) ([]string, error)
	Exists(ctx context.Context, name string) (bool, error)
}

type StoreOptions struct {
	ContentType  string
	CacheControl string
	Metadata     map[string]string
}

type FileInfo struct {
	Name         string
	URL          string
	Path         string
	Size         int64
	ContentType  string
	LastModified time.Time
	Metadata     map[string]string
}

func AvatarPath(userID string) string {
	return path.Join(PathAvatars, userID+".jpg")
}
