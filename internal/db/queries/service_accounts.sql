-- name: CreateServiceAccount :one
INSERT INTO
  service_accounts (workspace_id, name, description, role_name, expires_at, tags, token_hash)
VALUES
  (
    @workspace_id,
    @name,
    @description,
    COALESCE(sqlc.narg('role_name')::TEXT, 'viewer'),
    @expires_at,
    COALESCE(@tags, '{}'::TEXT[]),
    @token_hash
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

-- name: GetServiceAccountWorkspaceID :one
SELECT
  workspace_id
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
  sa.workspace_id = @workspace_id
  AND (
    sqlc.narg('query')::TEXT IS NULL
    OR sa.name ILIKE '%' || sqlc.narg('query') || '%'
    OR COALESCE(sa.description, '') ILIKE '%' || sqlc.narg('query') || '%'
  )
  AND sa.tags @> COALESCE(sqlc.narg('tags'), '{}'::TEXT[])
  AND (
    sqlc.narg('is_active')::BOOLEAN IS NULL
    OR (
      sqlc.narg('is_active') = TRUE
      AND (
        sa.expires_at IS NULL
        OR sa.expires_at > NOW()
      )
    )
    OR (
      sqlc.narg('is_active') = FALSE
      AND sa.expires_at IS NOT NULL
      AND sa.expires_at <= NOW()
    )
  )
  AND (
    sqlc.narg('role_name')::TEXT IS NULL
    OR sa.role_name = sqlc.narg('role_name')::TEXT
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
  role_name = COALESCE(sqlc.narg('role_name'), role_name),
  tags = COALESCE(sqlc.narg('tags'), tags)
WHERE
  id = @service_account_id
RETURNING
  id;

-- name: DeleteServiceAccount :exec
DELETE FROM service_accounts
WHERE
  id = @service_account_id;

-- Bearer-token authentication for service accounts: resolve by the stored
-- hash of the raw secret. A service account's token is its credential, so
-- only live, unexpired accounts match.
-- name: GetServiceAccountByTokenHash :one
SELECT
  *
FROM
  service_accounts
WHERE
  token_hash = @token_hash
  AND (expires_at IS NULL OR expires_at > NOW());

-- name: TouchServiceAccount :exec
UPDATE service_accounts
SET
  last_used_at = NOW()
WHERE
  id = @id;
