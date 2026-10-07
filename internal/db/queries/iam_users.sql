-- name: CreateUser :one
INSERT INTO
  users (workspace_id, email, name, role, picture)
VALUES
  (@workspace_id, @email, @name, @role, sqlc.narg('picture'))
RETURNING
  *;

-- name: CreateUserWithID :one
INSERT INTO
  users (id, workspace_id, email, name, role, picture)
VALUES
  (@id, @workspace_id, @email, @name, @role, sqlc.narg('picture'))
RETURNING
  *;

-- name: GetUser :one
SELECT
  *
FROM
  users
WHERE
  workspace_id = @workspace_id
  AND id = @id;

-- name: GetUserByEmail :one
SELECT
  *
FROM
  users
WHERE
  workspace_id = @workspace_id
  AND email = @email;

-- name: GetOwner :one
SELECT
  *
FROM
  users
WHERE
  workspace_id = @workspace_id
  AND role = 'owner';

-- name: ListUsers :many
SELECT
  sqlc.embed(u),
  COUNT(*) OVER ()::INTEGER AS total_count
FROM
  users u
WHERE
  u.workspace_id = @workspace_id
  AND (
    sqlc.narg('query')::TEXT IS NULL
    OR u.name ILIKE '%' || sqlc.narg('query') || '%'
    OR u.email ILIKE '%' || sqlc.narg('query') || '%'
  )
  AND (
    sqlc.narg('role')::TEXT IS NULL
    OR u.role = sqlc.narg('role')::TEXT
  )
ORDER BY
  u.name ASC,
  u.email ASC
LIMIT
  sqlc.narg('limit')
OFFSET
  sqlc.narg('offset');

-- name: CountActiveUsers :one
SELECT
  COUNT(*)
FROM
  users
WHERE
  workspace_id = @workspace_id
  AND active;

-- name: UpdateUser :one
UPDATE users
SET
  name = COALESCE(sqlc.narg('name'), name),
  picture = COALESCE(sqlc.narg('picture'), picture),
  updated_at = NOW()
WHERE
  workspace_id = @workspace_id
  AND id = @id
RETURNING
  *;

-- name: UpdateUserRole :exec
-- Never touches the owner, see TransferOwnership.
UPDATE users
SET
  role = @role,
  updated_at = NOW()
WHERE
  workspace_id = @workspace_id
  AND id = @id
  AND role <> 'owner';

-- name: SetUserActive :exec
UPDATE users
SET
  active = @active,
  updated_at = NOW()
WHERE
  workspace_id = @workspace_id
  AND id = @id
  AND role <> 'owner';

-- name: TransferOwnership :execrows
-- One statement, so the partial unique index on the owner never sees two.
UPDATE users
SET
  role = CASE
    WHEN id = @new_owner_id THEN 'owner'
    ELSE 'admin'
  END,
  updated_at = NOW()
WHERE
  workspace_id = @workspace_id
  AND (
    role = 'owner'
    OR (
      id = @new_owner_id
      AND active
    )
  );

-- name: SetUserEmail :one
UPDATE users
SET
  email = @email,
  updated_at = NOW()
WHERE
  workspace_id = @workspace_id
  AND id = @id
RETURNING
  *;

-- name: DeleteUser :exec
DELETE FROM users
WHERE
  workspace_id = @workspace_id
  AND id = @id
  AND role <> 'owner';
