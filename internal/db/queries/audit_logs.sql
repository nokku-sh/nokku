-- name: InsertAuditLog :exec
INSERT INTO
  audit.audit_logs (workspace_id, action, actor_id, actor_type, actor_email, ip_address, user_agent, status_code, details)
VALUES
  (
    sqlc.narg('workspace_id')::UUID,
    sqlc.arg('action'),
    sqlc.narg('actor_id')::UUID,
    sqlc.arg('actor_type'),
    sqlc.narg('actor_email'),
    sqlc.narg('ip_address'),
    sqlc.narg('user_agent'),
    sqlc.narg('status_code'),
    sqlc.arg('details')::jsonb
  );

-- name: ListAuditLogs :many
SELECT
  *
FROM
  audit.audit_logs
WHERE
  (
    (
      NULLIF(sqlc.arg('workspace_id')::TEXT, '')::UUID IS NULL
      AND workspace_id IS NULL
    )
    OR workspace_id = NULLIF(sqlc.arg('workspace_id')::TEXT, '')::UUID
  )
  AND (
    sqlc.narg('actor_ids')::TEXT[] IS NULL
    OR actor_id = ANY (sqlc.narg('actor_ids')::TEXT[])
  )
  AND (
    sqlc.narg('actor_types')::TEXT[] IS NULL
    OR actor_type = ANY (sqlc.narg('actor_types')::TEXT[])
  )
  AND (
    sqlc.narg('actions')::TEXT[] IS NULL
    OR EXISTS (
      SELECT 1 FROM unnest(sqlc.narg('actions')::TEXT[]) AS a(v)
      WHERE action ILIKE '%' || a.v || '%'
    )
  )
  AND (
    sqlc.narg('search')::TEXT IS NULL
    OR action ILIKE '%' || sqlc.narg('search') || '%'
    OR actor_email ILIKE '%' || sqlc.narg('search') || '%'
    OR actor_id::TEXT ILIKE '%' || sqlc.narg('search') || '%'
    OR user_agent ILIKE '%' || sqlc.narg('search') || '%'
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

-- name: CountAuditLogs :one
SELECT
  COUNT(*)::INTEGER
FROM
  audit.audit_logs
WHERE
  (
    (
      NULLIF(sqlc.arg('workspace_id')::TEXT, '')::UUID IS NULL
      AND workspace_id IS NULL
    )
    OR workspace_id = NULLIF(sqlc.arg('workspace_id')::TEXT, '')::UUID
  )
  AND (
    sqlc.narg('actor_ids')::TEXT[] IS NULL
    OR actor_id = ANY (sqlc.narg('actor_ids')::TEXT[])
  )
  AND (
    sqlc.narg('actor_types')::TEXT[] IS NULL
    OR actor_type = ANY (sqlc.narg('actor_types')::TEXT[])
  )
  AND (
    sqlc.narg('actions')::TEXT[] IS NULL
    OR EXISTS (
      SELECT 1 FROM unnest(sqlc.narg('actions')::TEXT[]) AS a(v)
      WHERE action ILIKE '%' || a.v || '%'
    )
  )
  AND (
    sqlc.narg('search')::TEXT IS NULL
    OR action ILIKE '%' || sqlc.narg('search') || '%'
    OR actor_email ILIKE '%' || sqlc.narg('search') || '%'
    OR actor_id::TEXT ILIKE '%' || sqlc.narg('search') || '%'
    OR user_agent ILIKE '%' || sqlc.narg('search') || '%'
  )
  AND (
    sqlc.narg('start_date')::timestamptz IS NULL
    OR timestamp >= sqlc.narg('start_date')
  )
  AND (
    sqlc.narg('end_date')::timestamptz IS NULL
    OR timestamp < sqlc.narg('end_date')
  );

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
