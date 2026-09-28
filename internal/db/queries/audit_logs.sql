-- name: InsertAuditLog :exec
INSERT INTO
  audit.audit_logs (
    workspace_id,
    actor_id,
    actor_kind,
    actor_name,
    action,
    target,
    ok,
    ip,
    user_agent,
    details
  )
VALUES
  (
    sqlc.narg('workspace_id')::UUID,
    @actor_id,
    @actor_kind,
    @actor_name,
    @action,
    @target,
    @ok,
    @ip,
    @user_agent,
    @details::jsonb
  );

-- name: ListAuditLogs :many
-- A NULL workspace_id is the personal log, RLS already limits the rows.
SELECT
  *,
  COUNT(*) OVER ()::INTEGER AS total
FROM
  audit.audit_logs
WHERE
  (
    sqlc.narg('workspace_id')::UUID IS NULL
    OR workspace_id = sqlc.narg('workspace_id')::UUID
  )
  AND (
    sqlc.narg('actor_ids')::TEXT[] IS NULL
    OR actor_id = ANY (sqlc.narg('actor_ids')::TEXT[])
  )
  AND (
    sqlc.narg('actor_kinds')::TEXT[] IS NULL
    OR actor_kind = ANY (sqlc.narg('actor_kinds')::TEXT[])
  )
  -- Actions match exactly, a trailing * matches by prefix, e.g. "Delete*".
  AND (
    sqlc.narg('actions')::TEXT[] IS NULL
    OR action = ANY (sqlc.narg('actions')::TEXT[])
    OR EXISTS (
      SELECT
        1
      FROM
        unnest(sqlc.narg('actions')::TEXT[]) AS a (v)
      WHERE
        a.v LIKE '%*'
        AND action LIKE rtrim(a.v, '*') || '%'
    )
  )
  AND (
    sqlc.narg('target')::TEXT IS NULL
    OR target = sqlc.narg('target')
  )
  -- Failed is every failed call, denied only those an auth or permission check stopped.
  AND (
    sqlc.narg('outcome')::TEXT IS NULL
    OR (
      sqlc.narg('outcome') = 'succeeded'
      AND ok
    )
    OR (
      sqlc.narg('outcome') = 'denied'
      AND NOT ok
      AND (
        action = 'LoginDenied'
        OR details ->> 'code' IN ('permission_denied', 'unauthenticated')
      )
    )
    OR (
      sqlc.narg('outcome') = 'failed'
      AND NOT ok
    )
  )
  AND (
    sqlc.narg('search')::TEXT IS NULL
    OR action ILIKE '%' || sqlc.narg('search') || '%'
    OR actor_name ILIKE '%' || sqlc.narg('search') || '%'
    OR target ILIKE '%' || sqlc.narg('search') || '%'
  )
  AND (
    sqlc.narg('start_date')::timestamptz IS NULL
    OR timestamp >= sqlc.narg('start_date')
  )
  AND (
    sqlc.narg('end_date')::timestamptz IS NULL
    OR timestamp < sqlc.narg('end_date')
  )
ORDER BY
  timestamp DESC
LIMIT
  sqlc.arg('limit')
OFFSET
  sqlc.arg('offset');

-- name: ListWorkspaceAuditLogWorkspaceIDs :many
SELECT DISTINCT
  workspace_id
FROM
  audit.audit_logs
WHERE
  workspace_id IS NOT NULL;

-- name: DeleteWorkspaceAuditLogs :execrows
DELETE FROM audit.audit_logs
WHERE
  workspace_id = @workspace_id
  AND timestamp < @cutoff; 

-- name: DeleteOrphanAuditLogs :execrows
DELETE FROM audit.audit_logs
WHERE
  workspace_id IS NULL
  AND timestamp < @cutoff;

-- name: MaintainAuditPartitions :exec
SELECT
  audit.maintain_partitions ();

-- name: EnableAuditRetention :exec
-- Opts this transaction into the audit_logs delete guard.
SELECT
  set_config('nokku.audit_retention', 'on', TRUE);
