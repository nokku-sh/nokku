-- name: CreateRecording :one
-- The daemon names the start of a session it uploads late. A start before the
-- daemon enrolled or in the future is a clock that was wrong, and counts as
-- now, or retention would take the recording at once.
INSERT INTO
  recordings (id, daemon_id, daemon_name, username, key, started_at)
SELECT
  @id,
  d.id,
  d.name,
  @username,
  @key,
  CASE
    WHEN sqlc.narg('started_at')::TIMESTAMPTZ BETWEEN d.created_at AND NOW() THEN sqlc.narg('started_at')::TIMESTAMPTZ
    ELSE NOW()
  END
FROM
  daemons d
WHERE
  d.id = @daemon_id
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
  sqlc.embed(r),
  COUNT(*) OVER ()::INTEGER AS total_count
FROM
  recordings r
WHERE
  (
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
  recordings;

-- name: SetRecordingSize :exec
-- An upload in progress counts toward the storage cap by its row.
UPDATE recordings
SET
  size_bytes = @size_bytes
WHERE
  id = @id;

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
ORDER BY
  started_at ASC
LIMIT
  sqlc.narg('limit');

-- name: ListRecordingWorkspaceIDs :many
SELECT DISTINCT
  workspace_id
FROM
  recordings;

-- name: DeleteRecordingsBefore :many
DELETE FROM recordings
WHERE
  workspace_id = @workspace_id
  AND started_at < @cutoff
RETURNING
  id,
  size_bytes;
