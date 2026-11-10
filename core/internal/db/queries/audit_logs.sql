-- name: InsertAuditLog :exec
-- An event with an id of its own is stored once, however often it comes.
INSERT INTO
  audit.audit_logs (
    id,
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
    COALESCE(sqlc.narg('id')::UUID, uuidv7()),
    @workspace_id,
    @actor_id,
    @actor_kind,
    @actor_name,
    @action,
    @target,
    @ok,
    @ip,
    @user_agent,
    @details::jsonb
  )
ON CONFLICT (id) DO NOTHING;

-- name: ListAuditLogs :many
-- The total is counted on its own. A window count reads every matching row in full to return one page.
WITH
  filtered AS NOT MATERIALIZED (
    SELECT
      *
    FROM
      audit.audit_logs
    WHERE
      (
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
        sqlc.narg('excluded_actions')::TEXT[] IS NULL
        OR action <> ALL (sqlc.narg('excluded_actions')::TEXT[])
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
        -- The names an event stored, so "web-1" finds the grants on it.
        OR concat_ws(
          ' ',
          details ->> 'name',
          details ->> 'target',
          details ->> 'username',
          details ->> 'member',
          details ->> 'subject',
          details ->> 'subjects'
        ) ILIKE '%' || sqlc.narg('search') || '%'
      )
      AND (
        sqlc.narg('start_date')::timestamptz IS NULL
        OR timestamp >= sqlc.narg('start_date')
      )
      AND (
        sqlc.narg('end_date')::timestamptz IS NULL
        OR timestamp < sqlc.narg('end_date')
      )
  )
SELECT
  f.*,
  (
    SELECT
      COUNT(*)
    FROM
      filtered
  )::INTEGER AS total
FROM
  filtered f
ORDER BY
  f.timestamp DESC
LIMIT
  sqlc.arg('limit')
OFFSET
  sqlc.arg('offset');

-- name: ListWorkspaceAuditLogWorkspaceIDs :many
-- Hops from one workspace to the next in the index. A DISTINCT reads the whole log to name a few hundred ids.
WITH RECURSIVE
  w AS (
    (
      SELECT
        workspace_id
      FROM
        audit.audit_logs
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
          audit.audit_logs a
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

-- name: DeleteWorkspaceAuditLogs :execrows
-- An enabled stream holds what it has not sent yet, a paused one gives that up.
-- DeleteAuditLogsBefore still ends it at the longest retention.
DELETE FROM audit.audit_logs l
WHERE
  l.workspace_id = @workspace_id
  AND l.timestamp < @cutoff
  AND NOT EXISTS (
    SELECT
      1
    FROM
      audit_streams s
    WHERE
      s.workspace_id = @workspace_id
      AND s.enabled
      AND s.cursor_ts <= l.timestamp
  );

-- name: DeleteAuditLogsBefore :execrows
-- The longest retention for every row, also the ones whose workspace is gone.
DELETE FROM audit.audit_logs
WHERE
  timestamp < @cutoff;

-- name: EnableAuditRetention :exec
-- Opts this transaction into the audit_logs delete guard.
SELECT
  set_config('nokku.audit_retention', 'on', TRUE);

-- name: GetNames :many
-- Names for audit events in the order of the ids, an id that names nothing here gets an empty one.
SELECT
  COALESCE(NULLIF(u.name, ''), u.email, m.name, s.name, t.name, dt.name, '')::TEXT AS name
FROM
  unnest(@ids::UUID[]) WITH ORDINALITY AS i (id, n)
  LEFT JOIN users u ON u.id = i.id
  LEFT JOIN teams m ON m.id = i.id
  LEFT JOIN service_accounts s ON s.id = i.id
  LEFT JOIN targets t ON t.id = i.id
  LEFT JOIN targets dt ON dt.daemon_id = i.id -- a daemon goes by its server's name
ORDER BY
  i.n;
