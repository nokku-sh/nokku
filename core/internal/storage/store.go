package storage

import "path"

const pathVideos = "videos"

func RecordingPath(workspaceID, objectID string) string {
	return path.Join(pathVideos, workspaceID, objectID+".cast.gz")
}
