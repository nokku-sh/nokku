-- name: CreateRecording :one
-- A start before the daemon enrolled or in the future is a wrong clock and counts as now, or retention would take it.
INSERT INTO
  recordings (id, daemon_id, daemon_name, username, subject_id, subject_name, principal, key, started_at)
SELECT
  @id,
  d.id,
  d.name,
  @username,
  sqlc.narg('subject_id'),
  -- Subject ids are unique across kinds, so one of the two has it.
  COALESCE(
    (SELECT u.email FROM users u WHERE u.id = sqlc.narg('subject_id')),
    (SELECT sa.name FROM service_accounts sa WHERE sa.id = sqlc.narg('subject_id')),
    ''
  ),
  @principal,
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
-- The total is counted on its own. A window count reads every matching row in full to return one page.
WITH
  filtered AS NOT MATERIALIZED (
    SELECT
      f.id,
      f.started_at
    FROM
      recordings f
    WHERE
      (
        sqlc.narg('daemon_id')::UUID IS NULL
        OR f.daemon_id = sqlc.narg('daemon_id')
      )
      AND (
        sqlc.narg('username')::TEXT IS NULL
        OR f.username = sqlc.narg('username')
      )
      AND (
        sqlc.narg('subject_id')::UUID IS NULL
        OR f.subject_id = sqlc.narg('subject_id')
      )
  ),
  paginated AS (
    SELECT
      id
    FROM
      filtered
    ORDER BY
      started_at DESC
    LIMIT
      sqlc.narg('limit')
    OFFSET
      sqlc.narg('offset')
  )
SELECT
  sqlc.embed(r),
  (
    SELECT
      COUNT(*)
    FROM
      filtered
  )::INTEGER AS total_count,
  -- The same rule as ListOpenRecordings.
  (
    r.ended_at IS NULL
    AND r.started_at > NOW() - INTERVAL '24 hours'
    AND COALESCE(r.daemon_id = ANY (@connected::UUID[]), FALSE)
  )::BOOLEAN AS live
FROM
  recordings r
  JOIN paginated pp ON pp.id = r.id
ORDER BY
  r.started_at DESC;

-- name: SumRecordingBytes :one
SELECT
  COALESCE(SUM(size_bytes), 0)::BIGINT
FROM
  recordings;

-- name: LockRecording :one
-- Uploads of one recording end one at a time, so each sees what the one before it stored.
SELECT
  *
FROM
  recordings
WHERE
  id = @id
FOR UPDATE;

-- name: FinishRecordingUpload :one
-- A NULL object leaves the stored copy in place, a NULL end leaves a session running. An end from a wrong clock counts
-- as now.
UPDATE recordings
SET
  object_id = COALESCE(sqlc.narg('object_id')::UUID, object_id),
  size_bytes = @size_bytes,
  complete = @complete,
  ended_at = CASE
    WHEN sqlc.narg('ended_at')::TIMESTAMPTZ IS NULL THEN ended_at
    WHEN sqlc.narg('ended_at')::TIMESTAMPTZ BETWEEN started_at AND NOW() THEN sqlc.narg('ended_at')::TIMESTAMPTZ
    ELSE NOW()
  END
WHERE
  id = @id
RETURNING
  *;

-- name: QueueLostRecordingObject :exec
SELECT
  queue_lost_recording_object (@object_id);

-- name: DeleteRecording :execrows
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
-- Hops from one workspace to the next in the index. A DISTINCT reads every recording to name a few hundred ids.
WITH RECURSIVE
  w AS (
    (
      SELECT
        workspace_id
      FROM
        recordings
      ORDER BY
        workspace_id
      LIMIT
        1
    )
    UNION ALL
    SELECT
      (
        SELECT
          a.workspace_id
        FROM
          recordings a
        WHERE
          a.workspace_id > w.workspace_id
        ORDER BY
          a.workspace_id
        LIMIT
          1
      )
    FROM
      w
    WHERE
      w.workspace_id IS NOT NULL
  )
SELECT
  workspace_id::UUID
FROM
  w
WHERE
  workspace_id IS NOT NULL;

-- name: DeleteRecordingsBefore :exec
DELETE FROM recordings
WHERE
  workspace_id = @workspace_id
  AND started_at < @cutoff;

-- name: NextRecordingDelete :one
SELECT
  workspace_id,
  object_id
FROM
  recording_deletes
WHERE
  next_try_at <= NOW()
ORDER BY
  next_try_at
LIMIT
  1;

-- name: FinishRecordingDelete :exec
DELETE FROM recording_deletes
WHERE
  object_id = @object_id;

-- name: DeferRecordingDelete :exec
-- Waits 10 minutes after the first failure, doubling up to a day.
UPDATE recording_deletes
SET
  attempts = attempts + 1,
  last_error = @last_error,
  next_try_at = NOW() + LEAST(INTERVAL '1 day', INTERVAL '10 minutes' * POWER(2, LEAST(attempts, 10)))
WHERE
  object_id = @object_id;
