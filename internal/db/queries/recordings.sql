-- name: CreateRecording :one
INSERT INTO
  recordings (id, workspace_id, daemon_id, username)
VALUES
  (@id, @workspace_id, @daemon_id, @username)
RETURNING
  *;

-- name: GetRecording :one
SELECT
  *
FROM
  recordings
WHERE
  id = @id;

-- name: ListRecordings :many
SELECT
  r.*,
  COUNT(*) OVER ()::INTEGER AS total_count
FROM
  recordings r
WHERE
  r.workspace_id = @workspace_id
  AND (
    sqlc.narg('daemon_id')::UUID IS NULL
    OR r.daemon_id = sqlc.narg('daemon_id')
  )
  AND (
    sqlc.narg('username')::TEXT IS NULL
    OR r.username = sqlc.narg('username')
  )
ORDER BY
  r.started_at DESC
LIMIT
  sqlc.narg('limit')
OFFSET
  sqlc.narg('offset');

-- name: SumRecordingBytes :one
SELECT
  COALESCE(SUM(size_bytes), 0)::BIGINT
FROM
  recordings
WHERE
  workspace_id = @workspace_id;

-- name: SetRecordingComplete :one
UPDATE recordings
SET
  size_bytes = @size_bytes,
  ended_at = NOW(),
  complete = @complete
WHERE
  id = @id
RETURNING
  *;

-- name: DeleteRecording :exec
DELETE FROM recordings
WHERE
  id = @id;

-- name: OldestRecordings :many
SELECT
  *
FROM
  recordings
WHERE
  workspace_id = @workspace_id
ORDER BY
  started_at ASC
LIMIT
  sqlc.narg('limit');

-- name: DeleteWorkspaceRecordings :exec
DELETE FROM recordings
WHERE
  workspace_id = @workspace_id;
