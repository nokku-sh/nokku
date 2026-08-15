package storage

import (
	"context"
	"io"
	"path"
)

const (
	PathAvatars = "avatars"
	PathVideos  = "videos"
)

type Store interface {
	Store(ctx context.Context, name string, data []byte, opts StoreOptions) (*string, error)
	// CreateWriter opens a streaming writer for a new object. The object is
	// committed on Close, closing without writing still creates the object.
	CreateWriter(ctx context.Context, name string, opts StoreOptions) (io.WriteCloser, error)
	Reader(ctx context.Context, name string) (io.ReadCloser, error)
	Delete(ctx context.Context, name string) error
	DeletePrefix(ctx context.Context, prefix string) error
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

// RecordingPath returns the object key for a session recording: a single
// gzipped asciicast v2 file per session, assembled by the backend from the
// daemon's upload stream.
func RecordingPath(workspaceID, recordingID string) string {
	return path.Join(PathVideos, workspaceID, recordingID+".cast.gz")
}

// RecordingsPrefix returns the object key prefix covering every recording of
// a workspace (used for the wipe-on-key-change sweep).
func RecordingsPrefix(workspaceID string) string {
	return path.Join(PathVideos, workspaceID) + "/"
}
