-- name: CreateServiceAccount :one
INSERT INTO
  service_accounts (name, description, role, tags)
VALUES
  (
    @name,
    @description,
    @role,
    COALESCE(sqlc.narg('tags')::TEXT[], '{}')
  )
RETURNING
  id;

-- name: GetServiceAccount :one
SELECT
  *
FROM
  service_accounts
WHERE
  id = @service_account_id;

-- name: ListServiceAccounts :many
SELECT
  sqlc.embed(sa),
  COUNT(*) OVER ()::INTEGER AS total_count
FROM
  service_accounts sa
WHERE
  (
    sqlc.narg('query')::TEXT IS NULL
    OR sa.name ILIKE '%' || sqlc.narg('query') || '%'
    OR COALESCE(sa.description, '') ILIKE '%' || sqlc.narg('query') || '%'
  )
  AND (
    sqlc.narg('tags')::TEXT[] IS NULL
    OR sa.tags @> sqlc.narg('tags')::TEXT[]
  )
  AND (
    sa.role = @role
    OR @role = 0 -- every role
  )
ORDER BY
  sa.id ASC
LIMIT
  sqlc.narg('limit')
OFFSET
  sqlc.narg('offset');

-- name: UpdateServiceAccount :one
UPDATE service_accounts
SET
  name = COALESCE(sqlc.narg('name'), name),
  description = COALESCE(sqlc.narg('description'), description),
  -- 0 is unset and keeps the role. The column comes first, sqlc types the parameter by its first use.
  role = CASE
    WHEN role = @role
    OR @role = 0 THEN role
    ELSE @role
  END,
  tags = COALESCE(sqlc.narg('tags'), tags),
  updated_at = NOW()
WHERE
  id = @service_account_id
RETURNING
  id;

-- name: DeleteServiceAccount :exec
DELETE FROM service_accounts
WHERE
  id = @service_account_id;
