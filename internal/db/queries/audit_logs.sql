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
-- RLS already limits rows to the pinned workspace or the actor's own. A NULL
-- workspace_id is the personal log: every row of the actor, any workspace.
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
  -- Actions match by prefix, so "Delete" finds every delete.
  AND (
    sqlc.narg('actions')::TEXT[] IS NULL
    OR EXISTS (
      SELECT
        1
      FROM
        unnest(sqlc.narg('actions')::TEXT[]) AS a (v)
      WHERE
        action ILIKE a.v || '%'
    )
  )
  AND (
    sqlc.narg('target')::TEXT IS NULL
    OR target = sqlc.narg('target')
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
