package storage

import "path"

const (
	PathAvatars = "avatars"
	PathVideos  = "videos"
)

type StoreOptions struct {
	ContentType  string
	CacheControl string
}

func AvatarPath(userID string) string {
	return path.Join(PathAvatars, userID+".jpg")
}

// RecordingPath returns the object key for a session recording: a single
// gzipped asciicast v3 file per session, assembled by the backend from the
// daemon's upload stream.
func RecordingPath(workspaceID, recordingID string) string {
	return path.Join(PathVideos, workspaceID, recordingID+".cast.gz")
}
