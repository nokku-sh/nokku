-- name: CreateServiceAccount :one
INSERT INTO
  service_accounts (name, description, role, tags)
VALUES
  (
    @name,
    @description,
    @role,
    COALESCE(@tags, '{}'::TEXT[])
  )
RETURNING
  id;

-- name: GetServiceAccount :one
SELECT
  sqlc.embed(sa),
  -- sqlc types a cast as not null, so an account never used reads as the zero time.
  COALESCE(MAX(t.last_seen_at), '0001-01-01'::TIMESTAMPTZ)::TIMESTAMPTZ AS last_used_at
FROM
  service_accounts sa
  LEFT JOIN access_tokens t ON t.service_account_id = sa.id
WHERE
  sa.id = @service_account_id
GROUP BY
  sa.id;

-- name: ListServiceAccounts :many
SELECT
  sqlc.embed(sa),
  -- sqlc types a cast as not null, so an account never used reads as the zero time.
  COALESCE(MAX(t.last_seen_at), '0001-01-01'::TIMESTAMPTZ)::TIMESTAMPTZ AS last_used_at,
  COUNT(*) OVER ()::INTEGER AS total_count
FROM
  service_accounts sa
  LEFT JOIN access_tokens t ON t.service_account_id = sa.id
WHERE
  (
    sqlc.narg('query')::TEXT IS NULL
    OR sa.name ILIKE '%' || sqlc.narg('query') || '%'
    OR COALESCE(sa.description, '') ILIKE '%' || sqlc.narg('query') || '%'
  )
  AND sa.tags @> COALESCE(sqlc.narg('tags'), '{}'::TEXT[])
  AND (
    sa.role = @role
    OR @role = 0 -- every role
  )
GROUP BY
  sa.id
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
  -- 0 is unset and keeps the role. The column comes first in the condition,
  -- sqlc types the parameter by its first use.
  role = CASE
    WHEN role = @role
    OR @role = 0 THEN role
    ELSE @role
  END,
  tags = COALESCE(sqlc.narg('tags'), tags)
WHERE
  id = @service_account_id
RETURNING
  id;

-- name: DeleteServiceAccount :exec
DELETE FROM service_accounts
WHERE
  id = @service_account_id;
