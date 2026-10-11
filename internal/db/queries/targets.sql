-- name: CreateTarget :one
INSERT INTO
  targets (
    ca_id,
    name,
    description,
    endpoints,
    tags,
    metadata,
    host_public_key
  )
VALUES
  (
    @ca_id,
    @name,
    @description,
    @endpoints,
    COALESCE(@tags, '{}'::TEXT[]),
    COALESCE(@metadata, '{}'::JSONB),
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
    sqlc.narg('ca_id')::UUID IS NULL
    OR t.ca_id = sqlc.narg('ca_id')::UUID
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
  ca_id = COALESCE(sqlc.narg('ca_id'), ca_id),
  name = COALESCE(sqlc.narg('name'), name),
  description = COALESCE(sqlc.narg('description'), description),
  endpoints = COALESCE(sqlc.narg('endpoints'), endpoints),
  tags = COALESCE(sqlc.narg('tags'), tags),
  metadata = COALESCE(sqlc.narg('metadata'), metadata),
  host_public_key = COALESCE(sqlc.narg('host_public_key'), host_public_key)
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

-- name: UpdateTargetCA :one
-- No id means the workspace default.
UPDATE targets
SET
  ca_id = COALESCE(
    sqlc.narg('ca_id'),
    (
      SELECT
        id
      FROM
        ssh_cas
      WHERE
        workspace_id = targets.workspace_id
        AND is_default = TRUE
      LIMIT
        1
    )
  )
WHERE
  targets.daemon_id = @daemon_id
RETURNING
  *;

-- name: GetTargetsBySubject :many
-- For a user, grants to their teams count too. Subject UUIDs are unique across kinds.
SELECT
  t.*
FROM
  targets t
WHERE
  t.daemon_id = sqlc.arg('subject_id')::UUID
  OR t.id IN (
    SELECT
      p.target_id
    FROM
      grants g
      JOIN target_accounts p ON p.id = g.account_id
    WHERE
      -- One array of ids, an OR over the teams would keep the lookup off the subject index.
      g.subject_id = ANY (
        ARRAY[sqlc.arg('subject_id')::UUID] || ARRAY(
          SELECT
            tm.team_id
          FROM
            team_members tm
          WHERE
            tm.user_id = sqlc.arg('subject_id')::UUID
        )
      )
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

-- name: TouchTargetManualSync :exec
UPDATE targets
SET
  metadata = COALESCE(metadata, '{}'::jsonb)
    || jsonb_build_object(
      'last_manual_sync',
      to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
    )
WHERE
  id = @target_id;
