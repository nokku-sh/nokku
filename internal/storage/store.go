package storage

import (
	"context"
	"io"
	"path"
)

const (
	PathAvatars = "avatars"
)

type Store interface {
	Store(ctx context.Context, name string, data []byte, opts StoreOptions) (*string, error)
	Reader(ctx context.Context, name string) (io.ReadCloser, error)
	Delete(ctx context.Context, name string) error
	Exists(ctx context.Context, name string) (bool, error)
	PublicURL(name string) (string, bool)
}

type StoreOptions struct {
	ContentType  string
	CacheControl string
	Metadata     map[string]string
}

func AvatarPath(userID string) string {
	return path.Join(PathAvatars, userID+".jpg")
}
