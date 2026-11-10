-- name: CreateDaemon :one
-- Returns no row on a taken key, a racing enrollment of the same machine. CreateDaemonTarget names it.
INSERT INTO
  daemons (status, config, version, key_thumbprint, join_token_id, retire_after)
SELECT
  @status AS status,
  COALESCE(@config, '{}'::jsonb) AS config,
  @version AS version,
  @key_thumbprint AS key_thumbprint,
  sqlc.narg('join_token_id') AS join_token_id,
  sqlc.narg('retire_after') AS retire_after
ON CONFLICT DO NOTHING
RETURNING
  *;

-- name: CreateDaemonTarget :one
-- Returns no row on a taken name, also one a racing enrollment just took.
INSERT INTO
  targets (daemon_id, name)
VALUES
  (@daemon_id, @name)
ON CONFLICT DO NOTHING
RETURNING
  id;

-- name: GetDaemonByKeyThumbprint :one
SELECT
  sqlc.embed(d),
  t.id AS target_id,
  t.name
FROM
  daemons d
  JOIN targets t ON t.daemon_id = d.id
WHERE
  d.key_thumbprint = @key_thumbprint;

-- name: GetDaemon :one
SELECT
  sqlc.embed(d),
  t.name
FROM
  daemons d
  JOIN targets t ON t.daemon_id = d.id
WHERE
  d.id = @daemon_id;

-- name: ListDaemonsForSync :many
-- Every daemon of the workspace with its server, for the pass that works out what each one is told.
SELECT
  sqlc.embed(d),
  t.id AS target_id
FROM
  daemons d
  JOIN targets t ON t.daemon_id = d.id;

-- name: GetTargetByDaemon :one
SELECT
  *
FROM
  targets
WHERE
  daemon_id = @daemon_id;

-- name: GetDaemonsByIDs :many
SELECT
  sqlc.embed(d),
  t.name
FROM
  daemons d
  JOIN targets t ON t.daemon_id = d.id
WHERE
  d.id = ANY (sqlc.arg('daemon_ids')::UUID[]);

-- name: GetDaemonConfigForUpdate :one
SELECT
  config
FROM
  daemons
WHERE
  id = @daemon_id
FOR UPDATE;

-- name: UpdateDaemon :one
UPDATE daemons d
SET
  -- 0 is unset and keeps the status. The column comes first, sqlc types the parameter by its first use.
  status = CASE
    WHEN d.status = @status
    OR @status = 0 THEN d.status
    ELSE @status
  END,
  config = COALESCE(sqlc.narg('config'), d.config),
  updated_at = NOW()
FROM
  targets t
WHERE
  d.id = @daemon_id
  AND t.daemon_id = d.id
RETURNING
  t.name;

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
  t.name,
  COUNT(*) OVER ()::INTEGER AS total_count
FROM
  daemons d
  JOIN targets t ON t.daemon_id = d.id
WHERE
  (
    sqlc.narg('query')::TEXT IS NULL
    OR t.name ILIKE '%' || sqlc.narg('query') || '%'
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
-- The target goes with it, so the name is read before the cascade.
DELETE FROM daemons d
WHERE
  d.id = @daemon_id
RETURNING
  COALESCE((SELECT t.name FROM targets t WHERE t.daemon_id = d.id), '')::TEXT AS name;

-- name: GetOfflineDaemonByTokenAndName :one
-- The one an ephemeral enrollment of the same name may replace. A daemon that is connected keeps its name.
SELECT
  d.id
FROM
  daemons d
  JOIN targets t ON t.daemon_id = d.id
WHERE
  d.join_token_id = @join_token_id
  AND t.name = @name
  AND NOT COALESCE(d.id = ANY (@connected::UUID[]), FALSE);

-- name: DeleteRetiredDaemons :many
-- Across workspaces, so it runs as the system. A daemon never seen counts from its creation, a connected one stays.
-- Nothing counts from before the core started, a crash stamps no daemon as gone.
DELETE FROM daemons d
WHERE
  d.retire_after IS NOT NULL
  AND GREATEST(COALESCE(d.last_seen_at, d.created_at), @started_at::TIMESTAMPTZ) < NOW() - d.retire_after
  AND NOT COALESCE(d.id = ANY (@connected::UUID[]), FALSE)
RETURNING
  d.id,
  d.workspace_id,
  COALESCE((SELECT t.name FROM targets t WHERE t.daemon_id = d.id), '')::TEXT AS name;
