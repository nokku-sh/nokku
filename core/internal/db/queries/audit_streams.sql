-- name: CreateAuditStream :one
-- A new stream starts with the events from now on. Never the secret back, it is not shown again.
INSERT INTO
  audit_streams (kind, url, secret)
VALUES
  (@kind, @url, @secret)
RETURNING
  id,
  kind,
  url,
  enabled,
  last_sent_at,
  last_error,
  failing_since,
  created_at;

-- name: CountAuditStreams :one
SELECT
  COUNT(*)::INTEGER
FROM
  audit_streams;

-- name: ListAuditStreams :many
SELECT
  id,
  kind,
  url,
  enabled,
  last_sent_at,
  last_error,
  failing_since,
  created_at
FROM
  audit_streams
ORDER BY
  created_at;

-- name: GetAuditStream :one
SELECT
  *
FROM
  audit_streams
WHERE
  id = @id;

-- name: UpdateAuditStream :one
-- A new secret replaces the old one, none keeps it. Enabling clears a failure, so the next tick tries at once.
UPDATE audit_streams
SET
  url = COALESCE(sqlc.narg('url'), url),
  secret = COALESCE(sqlc.narg('secret'), secret),
  enabled = COALESCE(sqlc.narg('enabled'), enabled),
  retry_at = NULL
WHERE
  id = @id
RETURNING
  id,
  kind,
  url,
  enabled,
  last_sent_at,
  last_error,
  failing_since,
  created_at;

-- name: DeleteAuditStream :execrows
DELETE FROM audit_streams
WHERE
  id = @id;

-- name: ListDueAuditStreams :many
-- Every enabled stream whose wait after a failure is over, across workspaces.
SELECT
  *
FROM
  audit_streams
WHERE
  enabled
  AND (
    retry_at IS NULL
    OR retry_at <= NOW()
  )
ORDER BY
  id;

-- name: ListAuditLogsAfter :many
-- The events after the cursor in a stable order. A row is stamped when its insert starts and commits a moment
-- later, so the newest seconds wait until nothing older can still arrive.
SELECT
  *
FROM
  audit.audit_logs a
WHERE
  a.workspace_id = @workspace_id
  AND (a.timestamp, a.id) > (@cursor_ts::TIMESTAMPTZ, @cursor_id::UUID)
  AND a.timestamp < NOW() - INTERVAL '10 seconds'
ORDER BY
  a.timestamp,
  a.id
LIMIT
  @max_rows;

-- name: AdvanceAuditStream :exec
-- Only the stamps, so a delivery wakes no console. It moves only from where the batch was read.
UPDATE audit_streams
SET
  cursor_ts = @cursor_ts,
  cursor_id = @cursor_id,
  last_sent_at = NOW()
WHERE
  id = @id
  AND cursor_ts = @from_ts
  AND cursor_id = @from_id;

-- name: ClearAuditStreamFailure :exec
UPDATE audit_streams
SET
  last_error = '',
  failing_since = NULL,
  retry_at = NULL
WHERE
  id = @id;

-- name: FailAuditStream :exec
UPDATE audit_streams
SET
  last_error = @last_error,
  failing_since = COALESCE(failing_since, NOW()),
  retry_at = NOW() + @wait::INTERVAL
WHERE
  id = @id;
