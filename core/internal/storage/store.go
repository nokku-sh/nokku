package storage

import "path"

const (
	pathAvatars = "avatars"
	pathVideos  = "videos"
)

type StoreOptions struct {
	ContentType  string
	CacheControl string
}

func AvatarPath(userID string) string {
	return path.Join(pathAvatars, userID+".jpg")
}

func RecordingPath(workspaceID, recordingID string) string {
	return path.Join(pathVideos, workspaceID, recordingID+".cast.gz")
}

func RecordingPrefix(workspaceID string) string {
	return path.Join(pathVideos, workspaceID) + "/"
}
