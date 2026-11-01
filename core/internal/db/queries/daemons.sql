-- name: CreateDaemon :one
-- Returns no row on a taken name or key, so the caller can retry in its tx. A target of that name counts as
-- taken too, checked up front because its insert would otherwise abort the tx.
WITH
  new_daemon AS (
    INSERT INTO
      daemons (name, status, config, version, key_thumbprint, join_token_id, retire_after)
    SELECT
      @name AS name,
      @status AS status,
      COALESCE(@config, '{}'::jsonb) AS config,
      @version AS version,
      @key_thumbprint AS key_thumbprint,
      sqlc.narg('join_token_id') AS join_token_id,
      sqlc.narg('retire_after') AS retire_after
    WHERE
      NOT EXISTS (
        SELECT
          1
        FROM
          targets
        WHERE
          name = @name
      )
    ON CONFLICT DO NOTHING
    RETURNING
      *
  ),
  new_target AS (
    INSERT INTO
      targets (daemon_id, name)
    SELECT
      d.id,
      d.name
    FROM
      new_daemon d
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

-- name: GetDaemonConfigForUpdate :one
SELECT
  config
FROM
  daemons
WHERE
  id = @daemon_id
FOR UPDATE;

-- name: UpdateDaemon :one
UPDATE daemons
SET
  -- 0 is unset and keeps the status. The column comes first, sqlc types the parameter by its first use.
  status = CASE
    WHEN status = @status
    OR @status = 0 THEN status
    ELSE @status
  END,
  config = COALESCE(sqlc.narg('config'), config),
  updated_at = NOW()
WHERE
  id = @daemon_id
RETURNING
  *;

-- name: UpdateDaemonVersion :exec
-- Every sync reports it, so an unchanged value must not rewrite the row.
UPDATE daemons
SET
  version = @version
WHERE
  id = @daemon_id
  AND version <> @version;

-- name: MarkDaemonSeen :exec
UPDATE daemons
SET
  last_seen_at = NOW()
WHERE
  id = @daemon_id;

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
    d.status = @status
    OR @status = 0 -- every status
  )
  AND (
    sqlc.narg('online')::BOOLEAN IS NULL
    OR COALESCE(d.id = ANY (@connected::UUID[]), FALSE) = sqlc.narg('online')
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

-- name: GetOfflineDaemonByTokenAndName :one
-- The one an ephemeral enrollment of the same name may replace. A daemon that is connected keeps its name.
SELECT
  *
FROM
  daemons
WHERE
  join_token_id = @join_token_id
  AND name = @name
  AND NOT COALESCE(id = ANY (@connected::UUID[]), FALSE);

-- name: DeleteRetiredDaemons :many
-- Across workspaces, so it runs as the system. A daemon never seen counts from its creation, a connected one stays.
-- Nothing counts from before the core started, a crash stamps no daemon as gone.
DELETE FROM daemons
WHERE
  retire_after IS NOT NULL
  AND GREATEST(COALESCE(last_seen_at, created_at), @started_at::TIMESTAMPTZ) < NOW() - retire_after
  AND NOT COALESCE(id = ANY (@connected::UUID[]), FALSE)
RETURNING
  id,
  workspace_id,
  name;
