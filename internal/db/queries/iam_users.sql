-- name: CreateUser :one
INSERT INTO
  users (email, name, picture)
VALUES
  (@email, @name, sqlc.narg('picture'))
RETURNING
  *;

-- name: CreateUserWithID :one
INSERT INTO
  users (id, email, name, picture)
VALUES
  (@id, @email, @name, sqlc.narg('picture'))
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

-- name: UpdateUser :one
UPDATE users
SET
  name = COALESCE(sqlc.narg('name'), name),
  picture = COALESCE(sqlc.narg('picture'), picture),
  active = COALESCE(sqlc.narg('active'), active),
  disable_password_reset = COALESCE(sqlc.narg('disable_password_reset'), disable_password_reset)
WHERE
  id = @id
RETURNING
  *;

-- name: VerifyUserEmail :exec
UPDATE users
SET
  email_verified = TRUE
WHERE
  id = @id;

-- name: DeleteUser :exec
DELETE FROM users
WHERE
  id = @id;

-- name: DeleteUnverifiedUsers :execrows
DELETE FROM users
WHERE
  NOT email_verified
  AND created_at < @cutoff;
