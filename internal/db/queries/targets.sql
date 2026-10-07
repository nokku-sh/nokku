-- name: CreateTarget :one
INSERT INTO
  targets (
    workspace_id,
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
    @workspace_id,
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
  t.workspace_id = @workspace_id
  AND (
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
    sqlc.narg('principals')::TEXT[] IS NULL
    OR EXISTS (
      SELECT
        1
      FROM
        principals p
      WHERE
        p.target_id = t.id
        AND p.username = ANY (sqlc.narg('principals')::TEXT[])
    )
  )
  AND (
    sqlc.narg('tags')::TEXT[] IS NULL
    OR t.tags @> COALESCE(sqlc.narg('tags'), '{}'::TEXT[])
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
-- What a daemon reports about its host on every sync. Unchanged values must
-- not rewrite the row.
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
-- A workspace has a default per authority type, a target takes the SSH one (1).
UPDATE targets
SET
  ca_id = COALESCE(
    sqlc.narg('ca_id'),
    (
      SELECT
        id
      FROM
        certificate_authorities
      WHERE
        workspace_id = targets.workspace_id
        AND authority_type = 1
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
-- For a user, grants to their teams count too.
SELECT DISTINCT
  t.*
FROM
  targets t
WHERE
  t.daemon_id = sqlc.arg('subject_id')::UUID
  OR EXISTS (
    SELECT
      1
    FROM
      principals p
    WHERE
      p.target_id = t.id
      AND EXISTS (
        SELECT
          1
        FROM
          principal_grants g
        WHERE
          g.principal_id = p.id
          AND (
            -- Subject UUIDs are unique across kinds.
            g.subject_id = sqlc.arg('subject_id')::UUID
            OR (
              g.subject_kind = 'team'
              AND g.subject_id IN (
                SELECT
                  tm.team_id
                FROM
                  team_members tm
                WHERE
                  tm.user_id = sqlc.arg('subject_id')::UUID
              )
            )
          )
      )
  );

-- name: GetWorkspaceTags :many
SELECT DISTINCT
  unnest(tags)::TEXT AS tag
FROM
  targets
WHERE
  workspace_id = @workspace_id
ORDER BY
  tag ASC;

-- name: GetWorkspacePrincipals :many
SELECT DISTINCT
  username
FROM
  principals
WHERE
  workspace_id = @workspace_id
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
