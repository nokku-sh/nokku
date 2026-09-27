-- name: CreateDaemon :one
-- Returns no row when the name or the key is already taken, so the caller
-- can retry inside its transaction instead of aborting it.
WITH
  new_daemon AS (
    INSERT INTO
      daemons (workspace_id, name, status, config, metadata, key_thumbprint)
    VALUES
      (
        @workspace_id,
        @name,
        @status,
        COALESCE(@config, '{}'::jsonb),
        COALESCE(@metadata, '{}'::jsonb),
        @key_thumbprint
      )
    ON CONFLICT DO NOTHING
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
    RETURNING
      id
  )
SELECT
  d.*,
  t.id AS target_id
FROM
  new_daemon d
CROSS JOIN
  new_target t;

-- name: GetDaemonByKeyThumbprint :one
SELECT
  *
FROM
  daemons
WHERE
  workspace_id = @workspace_id
  AND key_thumbprint = @key_thumbprint;

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

-- name: UpdateDaemon :one
UPDATE daemons
SET
  status = COALESCE(sqlc.narg('status'), status),
  config = COALESCE(sqlc.narg('config'), config),
  metadata = COALESCE(sqlc.narg('metadata'), metadata)
WHERE
  id = @daemon_id
RETURNING
  *;

-- name: UpdateDaemonStatus :one
UPDATE daemons
SET
  status = @status
WHERE
  id = @daemon_id
RETURNING
  *;

-- name: UpdateDaemonMetadata :exec
UPDATE daemons
SET
  metadata = @metadata
WHERE
  id = @daemon_id;

-- name: SetDaemonsOnline :exec
UPDATE daemons
SET
  online = @online
WHERE
  id = ANY (@daemon_ids::UUID[]);

-- name: ListDaemons :many
SELECT
  sqlc.embed(d),
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
