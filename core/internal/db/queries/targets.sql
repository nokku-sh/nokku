-- name: CreateTarget :one
INSERT INTO
  targets (
    name,
    description,
    endpoints,
    tags,
    metadata,
    host_public_key
  )
VALUES
  (
    @name,
    @description,
    @endpoints,
    COALESCE(sqlc.narg('tags')::TEXT[], '{}'),
    COALESCE(sqlc.narg('metadata')::JSONB, '{}'),
    sqlc.narg('host_public_key')
  )
RETURNING
  *;

-- name: GetTarget :one
SELECT
  *
FROM
  targets
WHERE
  id = @target_id;

-- name: ListTargets :many
SELECT
  sqlc.embed(t),
  COUNT(*) OVER ()::INTEGER AS total_count
FROM
  targets t
WHERE
  (
    sqlc.narg('query')::TEXT IS NULL
    OR t.name ILIKE '%' || sqlc.narg('query') || '%'
    OR COALESCE(t.description, '') ILIKE '%' || sqlc.narg('query') || '%'
  )
  AND (
    sqlc.narg('daemon_id')::UUID IS NULL
    OR t.daemon_id = sqlc.narg('daemon_id')::UUID
  )
  AND (
    sqlc.narg('accounts')::TEXT[] IS NULL
    OR EXISTS (
      SELECT
        1
      FROM
        target_accounts p
      WHERE
        p.target_id = t.id
        AND p.username = ANY (sqlc.narg('accounts')::TEXT[])
    )
  )
  AND (
    sqlc.narg('tags')::TEXT[] IS NULL
    OR t.tags @> sqlc.narg('tags')::TEXT[]
  )
ORDER BY
  t.id ASC
LIMIT
  sqlc.narg('limit')
OFFSET
  sqlc.narg('offset');

-- name: UpdateTarget :one
UPDATE targets
SET
  name = COALESCE(sqlc.narg('name'), name),
  description = COALESCE(sqlc.narg('description'), description),
  endpoints = COALESCE(sqlc.narg('endpoints'), endpoints),
  tags = COALESCE(sqlc.narg('tags'), tags),
  metadata = COALESCE(sqlc.narg('metadata'), metadata),
  host_public_key = COALESCE(sqlc.narg('host_public_key'), host_public_key),
  updated_at = NOW()
WHERE
  id = @target_id
RETURNING
  *;

-- name: UpdateTargetReport :exec
-- What a daemon reports about its host on every sync. Unchanged values must not rewrite the row.
UPDATE targets
SET
  endpoints = COALESCE(sqlc.narg('endpoints'), endpoints),
  metadata = @metadata
WHERE
  id = @target_id
  AND (
    COALESCE(sqlc.narg('endpoints')::TEXT[], endpoints) IS DISTINCT FROM endpoints
    OR metadata IS DISTINCT FROM @metadata::jsonb
  );

-- name: DeleteTarget :one
DELETE FROM targets
WHERE
  id = @target_id
RETURNING
  *;

-- name: GetTargetsBySubject :many
-- The targets a person or service account holds an account on, a team's own for a team, a daemon's for a daemon.
SELECT
  t.*
FROM
  targets t
WHERE
  t.daemon_id = sqlc.arg('subject_id')::UUID
  OR t.id IN (
    SELECT
      e.target_id
    FROM
      effective_access e
    WHERE
      e.subject_id = sqlc.arg('subject_id')::UUID
  )
  OR t.id IN (
    SELECT
      p.target_id
    FROM
      live_grants g
      JOIN target_accounts p ON p.id = g.account_id
    WHERE
      g.team_id = sqlc.arg('subject_id')::UUID
  );

-- name: GetWorkspaceTags :many
SELECT DISTINCT
  unnest(tags)::TEXT AS tag
FROM
  targets
ORDER BY
  tag ASC;

-- name: GetWorkspaceAccounts :many
SELECT DISTINCT
  username
FROM
  target_accounts
ORDER BY
  username ASC;

-- name: ReportManualSync :exec
-- What nk sync reports about a host without a daemon. An empty value keeps what the target has, and an
-- unchanged report writes nothing. It is no edit, so updated_at stays.
UPDATE targets
SET
  endpoints = COALESCE(NULLIF(sqlc.narg('endpoints')::TEXT[], '{}'), endpoints),
  host_public_key = COALESCE(sqlc.narg('host_public_key'), host_public_key)
WHERE
  id = @target_id
  AND (
    COALESCE(NULLIF(sqlc.narg('endpoints')::TEXT[], '{}'), endpoints) IS DISTINCT FROM endpoints
    OR COALESCE(sqlc.narg('host_public_key'), host_public_key) IS DISTINCT FROM host_public_key
  );

-- name: TouchTargetSync :exec
-- On its own, a statement that sets the stamp with another column would tell every console.
UPDATE targets
SET
  last_sync_at = NOW()
WHERE
  id = @target_id;
