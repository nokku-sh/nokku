-- name: CreateTarget :one
INSERT INTO
  targets (workspace_id, ca_id, name, description, endpoints, tags, metadata)
VALUES
  (
    @workspace_id,
    @ca_id,
    @name,
    @description,
    @endpoints,
    COALESCE(@tags, '{}'::TEXT[]),
    COALESCE(@metadata, '{}'::JSONB)
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
  *
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

-- name: CountTargets :one
SELECT
  COUNT(*)::INTEGER
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
  AND t.tags @> COALESCE(sqlc.narg('tags'), '{}'::TEXT[]);

-- name: UpdateTarget :one
UPDATE targets
SET
  ca_id = COALESCE(sqlc.narg('ca_id'), ca_id),
  name = COALESCE(sqlc.narg('name'), name),
  description = COALESCE(sqlc.narg('description'), description),
  endpoints = COALESCE(sqlc.narg('endpoints'), endpoints),
  tags = COALESCE(sqlc.narg('tags'), tags),
  metadata = COALESCE(sqlc.narg('metadata'), metadata)
WHERE
  id = @target_id
RETURNING
  *;

-- name: DeleteTarget :one
DELETE FROM targets
WHERE
  id = @target_id
RETURNING
  *;

-- name: UpdateTargetCA :one
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
SELECT DISTINCT
  t.*
FROM
  targets t
  LEFT JOIN principals p ON p.target_id = t.id
  LEFT JOIN principal_users pu ON pu.principal_id = p.id
  AND pu.user_id = sqlc.arg('subject_id')::UUID
  LEFT JOIN principal_teams pt ON pt.principal_id = p.id
  AND pt.team_id = sqlc.arg('subject_id')::UUID
  LEFT JOIN principal_service_accounts psa ON psa.principal_id = p.id
  AND psa.service_account_id = sqlc.arg('subject_id')::UUID
WHERE
    t.daemon_id = sqlc.arg('subject_id')::UUID
  OR pu.user_id IS NOT NULL
  OR pt.team_id IS NOT NULL
  OR psa.service_account_id IS NOT NULL;

-- name: CheckTargetAccess :one
SELECT DISTINCT
  t.*
FROM
  targets t
  LEFT JOIN principals p ON p.target_id = t.id
  LEFT JOIN principal_users pu ON pu.principal_id = p.id
  AND pu.user_id = sqlc.arg('subject_id')::UUID
  LEFT JOIN principal_teams pt ON pt.principal_id = p.id
  AND pt.team_id = sqlc.arg('subject_id')::UUID
  LEFT JOIN principal_service_accounts psa ON psa.principal_id = p.id
  AND psa.service_account_id = sqlc.arg('subject_id')::UUID
WHERE
  t.id = sqlc.arg('target_id')::UUID
  AND (
    t.daemon_id = sqlc.arg('subject_id')::UUID
    OR pu.user_id IS NOT NULL
    OR pt.team_id IS NOT NULL
    OR psa.service_account_id IS NOT NULL
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
