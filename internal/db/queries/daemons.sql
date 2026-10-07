-- name: CreateDaemon :one
-- Returns no row on a taken name or key, so the caller can retry in its tx.
WITH
  new_daemon AS (
    INSERT INTO
      daemons (name, status, config, metadata, key_thumbprint)
    VALUES
      (
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
      targets (daemon_id, name, metadata)
    SELECT
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
  key_thumbprint = @key_thumbprint;

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
  last_seen_at
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

-- name: UpdateDaemonMetadata :exec
-- Every sync reports it, so an unchanged value must not rewrite the row.
UPDATE daemons
SET
  metadata = @metadata
WHERE
  id = @daemon_id
  AND metadata IS DISTINCT FROM @metadata::jsonb;

-- name: TouchDaemons :exec
UPDATE daemons
SET
  last_seen_at = NOW()
WHERE
  id = ANY (@daemon_ids::UUID[]);

-- name: ListDaemons :many
SELECT
  sqlc.embed(d),
  COUNT(*) OVER ()::INTEGER AS total_count
FROM
  daemons d
WHERE
  (
    sqlc.narg('query')::TEXT IS NULL
    OR d.name ILIKE '%' || sqlc.narg('query') || '%'
  )
  AND (
    sqlc.narg('status')::INTEGER IS NULL
    OR d.status = sqlc.narg('status')::INTEGER
  )
  AND (
    sqlc.narg('online')::BOOLEAN IS NULL
    OR COALESCE(d.last_seen_at > @seen_after::TIMESTAMPTZ, FALSE) = sqlc.narg('online')
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
