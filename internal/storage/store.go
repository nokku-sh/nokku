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

func RecordingPath(workspaceID, recordingID string) string {
	return path.Join(PathVideos, workspaceID, recordingID+".cast.gz")
}
