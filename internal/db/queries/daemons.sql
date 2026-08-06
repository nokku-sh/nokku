-- name: CreateDaemon :one
WITH
  new_daemon AS (
    INSERT INTO
      daemons (id, workspace_id, name, status, auth_method, auth_pubkey, config, metadata)
    VALUES
      (
        @id,
        @workspace_id,
        @name,
        @status,
        @auth_method,
        @auth_pubkey,
        COALESCE(@config, '{}'::jsonb),
        COALESCE(@metadata, '{}'::jsonb)
      )
    RETURNING
      *
  ),
  new_target AS (
    INSERT INTO
      targets (workspace_id, daemon_id, name, metadata)
    SELECT
      workspace_id,
      id,
      name,
      COALESCE(sqlc.narg('metadata'), '{}'::jsonb)
    FROM
      new_daemon
  )
SELECT
  *
FROM
  new_daemon;

-- name: GetDaemon :one
SELECT
  *
FROM
  daemons
WHERE
  id = @daemon_id;

-- name: GetTargetByDaemon :one
SELECT
  *
FROM
  targets
WHERE
  daemon_id = @daemon_id;

-- name: GetDaemonsByIDs :many
SELECT
  id,
  name,
  online
FROM
  daemons
WHERE
  id = ANY (sqlc.arg('daemon_ids')::UUID[]);

-- name: UpdateDaemon :exec
UPDATE daemons
SET
  config = COALESCE(sqlc.narg('config'), config),
  metadata = COALESCE(sqlc.narg('metadata'), metadata)
WHERE
  id = @daemon_id;

-- name: UpdateDaemonStatus :one
UPDATE daemons
SET
  status = @status
WHERE
  id = @daemon_id
RETURNING
  *;

-- name: UpdateDaemonOnlineStatus :exec
UPDATE daemons
SET
  online = @online
WHERE
  id = @daemon_id;

-- name: UpdateDaemonUsage :exec
UPDATE daemons
SET
  last_used_at = NOW(),
  online = TRUE
WHERE
  id = @daemon_id
  AND (
    last_used_at IS NULL
    OR last_used_at < NOW() - INTERVAL '5 minutes'
  );

-- name: ListDaemons :many
SELECT
  d.*,
  COUNT(*) OVER ()::INTEGER AS total_count
FROM
  daemons d
WHERE
  d.workspace_id = @workspace_id
  AND (
    sqlc.narg('query')::TEXT IS NULL
    OR d.name ILIKE '%' || sqlc.narg('query') || '%'
  )
  AND (
    sqlc.narg('status')::INTEGER IS NULL
    OR d.status = sqlc.narg('status')::INTEGER
  )
  AND (
    sqlc.narg('online')::BOOLEAN IS NULL
    OR d.online = sqlc.narg('online')
  )
ORDER BY
  d.id ASC
LIMIT
  sqlc.narg('limit')
OFFSET
  sqlc.narg('offset');

-- name: DeleteDaemon :one
DELETE FROM daemons
WHERE
  id = @daemon_id
RETURNING
  *;

-- name: SetDaemonsOffline :exec
UPDATE daemons
SET
  online = FALSE
WHERE
  online = TRUE;
