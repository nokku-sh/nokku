-- name: CreateUser :one
INSERT INTO
  users (email, name, role, picture)
VALUES
  (@email, @name, @role, sqlc.narg('picture'))
RETURNING
  *;

-- name: CreateUserWithID :one
INSERT INTO
  users (id, email, name, role, picture)
VALUES
  (@id, @email, @name, @role, sqlc.narg('picture'))
RETURNING
  *;

-- name: GetUser :one
SELECT
  *
FROM
  users
WHERE
  id = @id;

-- name: GetUserByEmail :one
SELECT
  *
FROM
  users
WHERE
  email = @email;

-- name: GetOwner :one
SELECT
  *
FROM
  users
WHERE
  role = 5; -- owner

-- name: ListUsers :many
SELECT
  sqlc.embed(u),
  COUNT(*) OVER ()::INTEGER AS total_count
FROM
  users u
WHERE
  (
    sqlc.narg('query')::TEXT IS NULL
    OR u.name ILIKE '%' || sqlc.narg('query') || '%'
    OR u.email ILIKE '%' || sqlc.narg('query') || '%'
  )
  AND (
    u.role = @role
    OR @role = 0 -- every role
  )
ORDER BY
  u.name ASC,
  u.email ASC
LIMIT
  sqlc.narg('limit')
OFFSET
  sqlc.narg('offset');

-- name: CountActiveUsers :one
-- Names the workspace, billing counts seats as nokku_system.
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
  id = @id
RETURNING
  *;

-- name: UpdateUserRole :exec
-- Never touches the owner, see TransferOwnership.
UPDATE users
SET
  role = @role,
  updated_at = NOW()
WHERE
  id = @id
  AND role <> 5; -- owner

-- name: SetUserActive :exec
UPDATE users
SET
  active = @active,
  updated_at = NOW()
WHERE
  id = @id
  AND role <> 5; -- owner

-- name: DemoteOwner :execrows
-- Runs before PromoteOwner. The partial unique index on the owner is checked row by row, so one statement
-- that swaps both can see two owners. See Queries.TransferOwnership.
UPDATE users
SET
  role = 4, -- admin
  updated_at = NOW()
WHERE
  role = 5; -- owner

-- name: PromoteOwner :execrows
UPDATE users
SET
  role = 5, -- owner
  updated_at = NOW()
WHERE
  id = @new_owner_id
  AND active;

-- name: SetUserEmail :one
UPDATE users
SET
  email = @email,
  updated_at = NOW()
WHERE
  id = @id
RETURNING
  *;

-- name: DeleteUser :exec
DELETE FROM users
WHERE
  id = @id
  AND role <> 5; -- owner

-- name: PutAvatar :exec
INSERT INTO
  user_avatars (user_id, image, etag)
VALUES
  (@user_id, @image, @etag)
ON CONFLICT (user_id) DO UPDATE
SET
  image = EXCLUDED.image,
  etag = EXCLUDED.etag,
  updated_at = NOW();

-- name: GetAvatar :one
SELECT
  image,
  etag,
  updated_at
FROM
  user_avatars
WHERE
  user_id = @user_id;

-- name: DeleteAvatar :exec
DELETE FROM user_avatars
WHERE
  user_id = @user_id;
