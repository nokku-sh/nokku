-- name: CreateDaemonTarget :one
-- Returns no row on a taken name, also one a racing enrollment just took.
INSERT INTO
  targets (name)
VALUES
  (@name)
ON CONFLICT DO NOTHING
RETURNING
  id;

-- name: CreateDaemon :one
-- Returns no row on a taken key, a racing enrollment of the same machine.
INSERT INTO
  daemons (target_id, accepted, config, version, key_thumbprint, join_token_id, retire_after)
SELECT
  @target_id AS target_id,
  @accepted AS accepted,
  COALESCE(@config, '{}'::jsonb) AS config,
  @version AS version,
  @key_thumbprint AS key_thumbprint,
  sqlc.narg('join_token_id') AS join_token_id,
  sqlc.narg('retire_after') AS retire_after
ON CONFLICT DO NOTHING
RETURNING
  *;

-- name: GetDaemonByKeyThumbprint :one
SELECT
  sqlc.embed(d),
  t.name
FROM
  daemons d
  JOIN targets t ON t.id = d.target_id
WHERE
  d.key_thumbprint = @key_thumbprint;

-- name: GetDaemon :one
SELECT
  sqlc.embed(d),
  t.name
FROM
  daemons d
  JOIN targets t ON t.id = d.target_id
WHERE
  d.target_id = @target_id;

-- name: ListDaemonsForSync :many
SELECT
  *
FROM
  daemons;

-- name: GetDaemonsByIDs :many
SELECT
  sqlc.embed(d),
  t.name
FROM
  daemons d
  JOIN targets t ON t.id = d.target_id
WHERE
  d.target_id = ANY (sqlc.arg('target_ids')::UUID[]);

-- name: GetDaemonConfigForUpdate :one
SELECT
  config
FROM
  daemons
WHERE
  target_id = @target_id
FOR UPDATE;

-- name: ApproveDaemon :one
UPDATE daemons d
SET
  accepted = TRUE,
  updated_at = NOW()
FROM
  targets t
WHERE
  d.target_id = @target_id
  AND t.id = d.target_id
RETURNING
  t.name;

-- name: UpdateDaemon :one
UPDATE daemons d
SET
  config = COALESCE(sqlc.narg('config'), d.config),
  updated_at = NOW()
FROM
  targets t
WHERE
  d.target_id = @target_id
  AND t.id = d.target_id
RETURNING
  t.name;

-- name: UpdateDaemonVersion :exec
-- Every sync reports it, so an unchanged value must not rewrite the row.
UPDATE daemons
SET
  version = @version
WHERE
  target_id = @target_id
  AND version <> @version;

-- name: MarkDaemonSeen :exec
UPDATE daemons
SET
  last_seen_at = NOW()
WHERE
  target_id = @target_id;

-- name: ListDaemons :many
SELECT
  sqlc.embed(d),
  t.name,
  COUNT(*) OVER ()::INTEGER AS total_count
FROM
  daemons d
  JOIN targets t ON t.id = d.target_id
WHERE
  (
    sqlc.narg('query')::TEXT IS NULL
    OR t.name ILIKE '%' || sqlc.narg('query') || '%'
  )
  AND (
    sqlc.narg('online')::BOOLEAN IS NULL
    OR COALESCE(d.target_id = ANY (@connected::UUID[]), FALSE) = sqlc.narg('online')
  )
ORDER BY
  d.target_id ASC
LIMIT
  sqlc.narg('limit')
OFFSET
  sqlc.narg('offset');

-- name: GetOfflineDaemonByTokenAndName :one
SELECT
  d.target_id
FROM
  daemons d
  JOIN targets t ON t.id = d.target_id
WHERE
  d.join_token_id = @join_token_id
  AND t.name = @name
  AND NOT COALESCE(d.target_id = ANY (@connected::UUID[]), FALSE);

-- name: DeleteRetiredDaemons :many
-- Nothing counts from before the core started, a crash stamps no daemon as gone.
DELETE FROM targets t USING daemons d
WHERE
  d.target_id = t.id
  AND d.retire_after IS NOT NULL
  AND GREATEST(COALESCE(d.last_seen_at, d.created_at), @started_at::TIMESTAMPTZ) < NOW() - d.retire_after
  AND NOT COALESCE(d.target_id = ANY (@connected::UUID[]), FALSE)
RETURNING
  t.id,
  t.workspace_id,
  t.name;

-- name: HasDaemon :one
SELECT
  EXISTS (
    SELECT
      1
    FROM
      daemons
    WHERE
      target_id = @target_id
  );
