package storage

import "path"

const pathVideos = "videos"

func RecordingPath(workspaceID, recordingID string) string {
	return path.Join(pathVideos, workspaceID, recordingID+".cast.gz")
}

func RecordingPrefix(workspaceID string) string {
	return path.Join(pathVideos, workspaceID) + "/"
}
