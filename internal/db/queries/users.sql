-- name: CreateUser :one
INSERT INTO
  users (name, username, picture, email, email_verified)
VALUES
  (@name, @username, @picture, @email, FALSE)
RETURNING
  *;

-- name: CreateOAuthUser :one
INSERT INTO
  users (name, username, picture, email, email_verified)
VALUES
  (@name, @username, @picture, @email, FALSE)
ON CONFLICT (email) DO NOTHING
RETURNING
  *;

-- name: GetUserByID :one
SELECT
  *
FROM
  users
WHERE
  id = @user_id;

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
  name = COALESCE(sqlc.narg(name), name),
  username = COALESCE(sqlc.narg(username), username),
  picture = COALESCE(sqlc.narg(picture), picture)
WHERE
  id = @user_id
RETURNING
  *;

-- name: UpdateEmailRecovery :exec
UPDATE users
SET
  enable_email_recovery = @enable_email_recovery
WHERE
  id = @user_id;

-- name: ListUsers :many
SELECT
  *
FROM
  users
ORDER BY
  created_at DESC;

-- name: DeleteUser :exec
DELETE FROM users
WHERE
  id = @user_id;

-- name: VerifyUserEmail :exec
UPDATE users
SET
  email = @email,
  email_verified = TRUE
WHERE
  id = @user_id;

-- name: EmailExists :one
SELECT
  EXISTS (
    SELECT
      1
    FROM
      users
    WHERE
      email = @email
  ) AS EXISTS;

-- name: DeleteUnverifiedUsers :exec
DELETE FROM users
WHERE
  NOT email_verified
  AND created_at < NOW() - INTERVAL '48 hours';
