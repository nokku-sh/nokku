-- name: CreateServiceAccount :one
INSERT INTO
  service_accounts (id, workspace_id, name, description, token_hash, expires_at, tags)
VALUES
  (
    @id,
    @workspace_id,
    @name,
    @description,
    @token_hash,
    @expires_at,
    COALESCE(@tags, '{}'::TEXT[])
  )
RETURNING
  *;

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
  *
FROM
  service_accounts
WHERE
  workspace_id = @workspace_id
  AND (
    sqlc.narg('query')::TEXT IS NULL
    OR name ILIKE '%' || sqlc.narg('query') || '%'
    OR COALESCE(description, '') ILIKE '%' || sqlc.narg('query') || '%'
  )
  AND tags @> COALESCE(@tags, '{}'::TEXT[])
  AND (
    sqlc.narg('is_active')::BOOLEAN IS NULL
    OR (
      sqlc.narg('is_active') = TRUE
      AND (
        expires_at IS NULL
        OR expires_at > NOW()
      )
    )
    OR (
      sqlc.narg('is_active') = FALSE
      AND expires_at IS NOT NULL
      AND expires_at <= NOW()
    )
  )
ORDER BY
  id ASC
LIMIT
  sqlc.narg('limit')
OFFSET
  sqlc.narg('offset');

-- name: CountServiceAccounts :one
SELECT
  COUNT(*)::INTEGER
FROM
  service_accounts
WHERE
  workspace_id = @workspace_id
  AND (
    sqlc.narg('query')::TEXT IS NULL
    OR name ILIKE '%' || sqlc.narg('query') || '%'
    OR COALESCE(description, '') ILIKE '%' || sqlc.narg('query') || '%'
  )
  AND tags @> COALESCE(@tags, '{}'::TEXT[]);

-- name: UpdateServiceAccount :one
UPDATE service_accounts
SET
  name = COALESCE(sqlc.narg('name'), name),
  description = COALESCE(sqlc.narg('description'), description),
  tags = COALESCE(sqlc.narg('tags'), tags)
WHERE
  id = @service_account_id
RETURNING
  *;

-- name: UpdateServiceAccountUsage :exec
UPDATE service_accounts
SET
  last_used_at = NOW()
WHERE
  id = @service_account_id
  AND (
    last_used_at IS NULL
    OR last_used_at < NOW() - INTERVAL '5 minutes'
  );

-- name: DeleteServiceAccount :one
DELETE FROM service_accounts
WHERE
  id = @service_account_id
RETURNING
  *;
