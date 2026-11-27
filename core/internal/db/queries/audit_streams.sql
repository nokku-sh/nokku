-- name: CreateAuditStream :one
-- The id comes from the caller, the secret is sealed to it.
INSERT INTO
  audit_streams (id, kind, url, secret)
VALUES
  (@id, @kind, @url, @secret)
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
  secret = COALESCE(sqlc.narg('secret')::sealed, secret),
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
-- Skips the newest minute, a row may commit after its stamp.
SELECT
  *
FROM
  audit.audit_logs a
WHERE
  a.workspace_id = @workspace_id
  AND (a.timestamp, a.id) > (@cursor_ts::TIMESTAMPTZ, @cursor_id::UUID)
  AND a.timestamp < NOW() - INTERVAL '60 seconds'
ORDER BY
  a.timestamp,
  a.id
LIMIT
  @max_rows;

-- name: AdvanceAuditStream :execrows
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
  failure_mailed_at = NULL,
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

-- name: ListAuditStreamsFailingLong :many
SELECT
  s.id,
  s.workspace_id,
  s.kind,
  s.url,
  s.last_error,
  s.failing_since::TIMESTAMPTZ AS failing_since,
  w.slug,
  w.name AS workspace_name,
  u.id AS owner_id,
  u.email AS owner_email
FROM
  audit_streams s
  JOIN workspaces w ON w.id = s.workspace_id
  JOIN users u ON u.workspace_id = s.workspace_id
  AND u.role = 5 -- owner
  AND u.active
WHERE
  s.enabled
  AND s.failure_mailed_at IS NULL
  AND s.failing_since < NOW() - @wait::INTERVAL;

-- name: SetAuditStreamFailureMailed :exec
UPDATE audit_streams
SET
  failure_mailed_at = NOW()
WHERE
  id = @id;
