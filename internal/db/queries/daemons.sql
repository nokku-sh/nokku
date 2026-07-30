-- name: CreateDaemon :one
WITH
  new_daemon AS (
    INSERT INTO
      daemons (id, workspace_id, name, status, token_hash, config, metadata)
    VALUES
      (
        @id,
        @workspace_id,
        @name,
        @status,
        @token_hash,
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
  *
FROM
  daemons
WHERE
  workspace_id = @workspace_id
  AND (
    sqlc.narg('query')::TEXT IS NULL
    OR name ILIKE '%' || sqlc.narg('query') || '%'
  )
  AND (
    sqlc.narg('status')::INTEGER IS NULL
    OR status = sqlc.narg('status')::INTEGER
  )
  AND (
    sqlc.narg('online')::BOOLEAN IS NULL
    OR online = sqlc.narg('online')
  )
ORDER BY
  id ASC
LIMIT
  sqlc.narg('limit')
OFFSET
  sqlc.narg('offset');

-- name: CountDaemons :one
SELECT
  COUNT(*)::INTEGER
FROM
  daemons
WHERE
  workspace_id = @workspace_id
  AND (
    sqlc.narg('query')::TEXT IS NULL
    OR name ILIKE '%' || sqlc.narg('query') || '%'
  );

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
