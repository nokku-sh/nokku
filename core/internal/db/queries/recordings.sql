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
  legal_hold_covers (r.workspace_id, r.started_at)::BOOLEAN AS held,
  (
    SELECT
      COUNT(*)
    FROM
      filtered
  )::INTEGER AS total_count
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

-- name: DeleteRecording :execrows
-- Nothing is deleted when a legal hold covers it.
DELETE FROM recordings r
WHERE
  r.id = @id
  AND NOT legal_hold_covers (r.workspace_id, r.started_at);

-- name: OldestRecordings :many
-- Held recordings are never evicted, so they are never offered.
SELECT
  r.*
FROM
  recordings r
WHERE
  NOT legal_hold_covers (r.workspace_id, r.started_at)
ORDER BY
  r.started_at ASC
LIMIT
  sqlc.narg('limit');

-- name: RecordingHeld :one
SELECT
  EXISTS (
    SELECT
      1
    FROM
      recordings r
    WHERE
      r.id = @id
      AND legal_hold_covers (r.workspace_id, r.started_at)
  )::BOOLEAN;

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

-- name: DeleteRecordingsBefore :many
-- A legal hold keeps its range.
DELETE FROM recordings r
WHERE
  r.workspace_id = @workspace_id
  AND r.started_at < @cutoff
  AND NOT legal_hold_covers (r.workspace_id, r.started_at)
RETURNING
  id,
  size_bytes;
