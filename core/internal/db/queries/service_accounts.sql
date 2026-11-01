-- name: CreateServiceAccount :one
INSERT INTO
  service_accounts (
    name,
    description,
    role,
    tags,
    force_command,
    source_address
  )
VALUES
  (
    @name,
    @description,
    @role,
    COALESCE(sqlc.narg('tags')::TEXT[], '{}'),
    @force_command,
    @source_address
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

-- name: GetServiceAccountByName :one
SELECT
  *
FROM
  service_accounts
WHERE
  name = @name;

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
  force_command = COALESCE(sqlc.narg('force_command'), force_command),
  source_address = COALESCE(sqlc.narg('source_address'), source_address),
  updated_at = NOW()
WHERE
  id = @service_account_id
RETURNING
  id;

-- name: DeleteServiceAccount :exec
DELETE FROM service_accounts
WHERE
  id = @service_account_id;

-- name: CreateServiceAccountFederation :one
INSERT INTO
  service_account_federations (service_account_id, issuer, claims)
VALUES
  (@service_account_id, @issuer, @claims)
RETURNING
  *;

-- name: ListServiceAccountFederations :many
SELECT
  *
FROM
  service_account_federations
WHERE
  service_account_id = @service_account_id
ORDER BY
  id ASC;

-- name: DeleteServiceAccountFederation :execrows
DELETE FROM service_account_federations
WHERE
  id = @id
  AND service_account_id = @service_account_id;
