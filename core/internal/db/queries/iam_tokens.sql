-- name: PutToken :exec
INSERT INTO
  one_time_tokens (token_hash, user_id, purpose, expires_at, email)
VALUES
  (@token_hash, @user_id, @purpose, @expires_at, sqlc.narg('email'));

-- name: ConsumeToken :one
-- Spends a token of a user. An invite has none, see ConsumeInvite.
DELETE FROM one_time_tokens
WHERE
  token_hash = @token_hash
  AND purpose = @purpose
  AND user_id IS NOT NULL
  AND expires_at > NOW()
RETURNING
  user_id::UUID AS user_id;

-- name: ConsumeEmailToken :one
DELETE FROM one_time_tokens
WHERE
  token_hash = @token_hash
  AND purpose = @purpose
  AND user_id IS NOT NULL
  AND email IS NOT NULL
  AND expires_at > NOW()
RETURNING
  user_id::UUID AS user_id,
  email::TEXT AS email;

-- name: DeleteUserTokens :exec
DELETE FROM one_time_tokens
WHERE
  user_id = @user_id
  AND purpose = @purpose;

-- name: DeleteAllUserTokens :exec
DELETE FROM one_time_tokens
WHERE
  user_id = @user_id;

-- name: GetPendingTokenEmail :one
SELECT
  email::TEXT AS email
FROM
  one_time_tokens
WHERE
  user_id = @user_id
  AND purpose = @purpose
  AND expires_at > NOW()
  AND email IS NOT NULL
ORDER BY
  created_at DESC
LIMIT
  1;

-- name: DeleteToken :exec
DELETE FROM one_time_tokens
WHERE
  token_hash = @token_hash;

-- name: DeleteExpiredTokens :execrows
-- Every tenant, runs as nokku_system.
DELETE FROM one_time_tokens
WHERE
  expires_at < @now;

-- name: PutInvite :exec
INSERT INTO
  one_time_tokens (token_hash, purpose, email, role, expires_at)
VALUES
  (@token_hash, 'invite', @email, @role, @expires_at);

-- name: GetInvite :one
SELECT
  email::TEXT AS email,
  role,
  expires_at
FROM
  one_time_tokens
WHERE
  token_hash = @token_hash
  AND purpose = 'invite'
  AND expires_at > NOW();

-- name: ConsumeInvite :one
DELETE FROM one_time_tokens
WHERE
  token_hash = @token_hash
  AND purpose = 'invite'
  AND expires_at > NOW()
RETURNING
  email::TEXT AS email,
  role;

-- name: ListInvites :many
SELECT
  email::TEXT AS email,
  role,
  expires_at,
  created_at
FROM
  one_time_tokens
WHERE
  purpose = 'invite'
  AND expires_at > NOW()
ORDER BY
  created_at DESC;

-- name: DeleteInvite :execrows
DELETE FROM one_time_tokens
WHERE
  purpose = 'invite'
  AND email = @email::TEXT;
