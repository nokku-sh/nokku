-- name: CreateUser :one
INSERT INTO
  users (name, username, password_hash, picture, email, email_verified)
VALUES
  (@name, @username, @password_hash, @picture, @email, FALSE)
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

-- name: DeleteUser :exec
DELETE FROM users
WHERE
  id = @user_id;

-- name: UpdateUserPassword :exec
UPDATE users
SET
  password_hash = @password_hash
WHERE
  id = @user_id;

-- name: DeleteUserPassword :exec
UPDATE users
SET
  password_hash = NULL
WHERE
  id = @user_id;

-- name: HasUserPassword :one
SELECT
  CASE
    WHEN password_hash IS NOT NULL THEN TRUE
    ELSE FALSE
  END AS has_password
FROM
  users
WHERE
  id = $1;

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

-- User Device Tokens ---------------------------------------------------------
-- name: CreateUserDevice :exec
INSERT INTO
  user_devices (id, user_id, name, kind, auth_method, auth_pubkey, token_hash)
VALUES
  (@id, @user_id, @name, @kind, @auth_method, @auth_pubkey, sqlc.narg('token_hash'))
RETURNING
  *;

-- name: GetUserDevice :one
SELECT
  *
FROM
  user_devices
WHERE
  id = @id;

-- name: GetUserWebDevice :one
SELECT
  token_hash,
  name
FROM
  user_devices
WHERE
  id = @id
  AND user_id = @user_id
  AND kind = 'web';

-- name: RotateUserDevice :one
UPDATE user_devices
SET
  auth_method = @auth_method,
  auth_pubkey = @auth_pubkey,
  token_hash = NULL,
  name = @name,
  expires_at = NOW() + INTERVAL '6 months'
WHERE
  id = @id
  AND user_id = @user_id
  AND kind = 'cli'
RETURNING
  id;

-- name: ListUserDevices :many
SELECT
  id,
  name,
  kind,
  expires_at,
  last_used_at,
  created_at
FROM
  user_devices
WHERE
  user_id = @user_id
ORDER BY
  created_at DESC;

-- name: UpdateUserDeviceUsage :exec
UPDATE user_devices
SET
  last_used_at = NOW(),
  expires_at = NOW() + INTERVAL '6 months'
WHERE
  id = @id
  AND (
    last_used_at IS NULL
    OR last_used_at < NOW() - INTERVAL '5 minutes'
  );

-- name: DeleteUserDevice :exec
DELETE FROM user_devices
WHERE
  id = @id
  AND user_id = @user_id;

-- name: DeleteExpiredUserDevices :exec
DELETE FROM user_devices
WHERE
  expires_at IS NOT NULL
  AND expires_at <= NOW();

-- Backup codes ---------------------------------------------------------------
-- name: CreateBackupCodes :exec
WITH
  deleted AS (
    DELETE FROM backup_codes
    WHERE
      user_id = @user_id
  )
INSERT INTO
  backup_codes (user_id, code_hash)
SELECT
  @user_id,
  unnest(@code_hashes::TEXT[]);

-- name: ListBackupCodes :many
SELECT
  *
FROM
  backup_codes
WHERE
  user_id = @user_id
  AND used_at IS NULL;

-- name: UseBackupCode :one
UPDATE backup_codes
SET
  used_at = NOW()
WHERE
  user_id = @user_id
  AND code_hash = @code_hash
  AND used_at IS NULL
RETURNING
  id;

-- name: DeleteBackupCodes :exec
DELETE FROM backup_codes
WHERE
  user_id = @user_id;
