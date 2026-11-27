-- name: CreateTarget :one
INSERT INTO
  targets (
    name,
    description,
    endpoints,
    tags,
    metadata,
    host_public_key,
    created_by
  )
VALUES
  (
    @name,
    @description,
    COALESCE(sqlc.narg('endpoints')::TEXT[], '{}'),
    COALESCE(sqlc.narg('tags')::TEXT[], '{}'),
    COALESCE(sqlc.narg('metadata')::JSONB, '{}'),
    @host_public_key,
    sqlc.narg('created_by')
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

-- name: LockTarget :one
SELECT
  *
FROM
  targets
WHERE
  id = @target_id
FOR UPDATE;

-- name: ListTargets :many
SELECT
  sqlc.embed(t),
  COUNT(*) OVER ()::INTEGER AS total_count
FROM
  targets t
  LEFT JOIN daemons d ON d.target_id = t.id
WHERE
  (
    sqlc.narg('query')::TEXT IS NULL
    OR t.name ILIKE '%' || sqlc.narg('query') || '%'
    OR t.description ILIKE '%' || sqlc.narg('query') || '%'
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
  AND (
    sqlc.narg('ids')::UUID[] IS NULL
    OR t.id = ANY (sqlc.narg('ids')::UUID[])
  )
  -- A server without a daemon learns a new CA key only from nk sync.
  AND (
    NOT @missed_rollover::BOOLEAN
    OR (
      d.target_id IS NULL
      AND t.manual_sync_at < (
        SELECT
          ca.rotated_at
        FROM
          ssh_cas ca
        WHERE
          ca.workspace_id = t.workspace_id
      )
    )
  )
  -- Online comes from the pool, the caller passes the daemons connected now.
  AND (
    sqlc.narg('status')::TEXT IS NULL
    OR (
      sqlc.narg('status') = 'pending'
      AND NOT d.accepted
    )
    OR (
      sqlc.narg('status') = 'online'
      AND d.accepted
      AND d.target_id = ANY (@connected::UUID[])
    )
    OR (
      sqlc.narg('status') = 'offline'
      AND d.accepted
      AND NOT COALESCE(d.target_id = ANY (@connected::UUID[]), FALSE)
    )
    OR (
      sqlc.narg('status') = 'manual'
      AND d.target_id IS NULL
    )
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
  updated_at = NOW()
WHERE
  targets.id = @target_id
RETURNING
  *;

-- name: UpdateTargetReport :exec
-- Unchanged values must not rewrite the row.
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
SELECT
  t.*
FROM
  targets t
WHERE
  t.id IN (
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
-- No key keeps the pinned one. It is no edit, so updated_at stays.
UPDATE targets
SET
  host_public_key = @host_public_key
WHERE
  id = @target_id
  AND @host_public_key <> ''
  AND host_public_key <> @host_public_key;

-- name: ForgetHostKey :exec
UPDATE targets
SET
  host_public_key = ''
WHERE
  id = @target_id;

-- name: TouchTargetSync :exec
-- On its own, a statement that sets the stamp with another column would tell every console.
UPDATE targets
SET
  manual_sync_at = NOW()
WHERE
  id = @target_id;
