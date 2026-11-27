-- name: PutToken :exec
INSERT INTO
  one_time_tokens (token_hash, user_id, purpose, expires_at, email)
VALUES
  (@token_hash, @user_id, @purpose, @expires_at, @email);

-- name: ConsumeToken :one
DELETE FROM one_time_tokens
WHERE
  token_hash = @token_hash
  AND purpose = @purpose
  AND expires_at > NOW()
RETURNING
  user_id;

-- name: ConsumeEmailToken :one
DELETE FROM one_time_tokens
WHERE
  token_hash = @token_hash
  AND purpose = @purpose
  AND expires_at > NOW()
RETURNING
  user_id,
  email,
  created_at;

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
  email
FROM
  one_time_tokens
WHERE
  user_id = @user_id
  AND purpose = @purpose
  AND expires_at > NOW()
ORDER BY
  created_at DESC
LIMIT
  1;

-- name: DeleteToken :exec
DELETE FROM one_time_tokens
WHERE
  token_hash = @token_hash;

-- name: DeleteExpiredTokens :execrows
DELETE FROM one_time_tokens
WHERE
  expires_at < @now;

-- name: PutInvite :exec
-- One pending invite per address, a new one replaces it.
INSERT INTO
  invites (token_hash, email, role, expires_at)
VALUES
  (@token_hash, @email, @role, @expires_at)
ON CONFLICT (workspace_id, email) DO UPDATE
SET
  token_hash = EXCLUDED.token_hash,
  role = EXCLUDED.role,
  expires_at = EXCLUDED.expires_at,
  created_at = NOW();

-- name: GetInvite :one
SELECT
  email,
  role,
  expires_at
FROM
  invites
WHERE
  token_hash = @token_hash
  AND expires_at > NOW();

-- name: ConsumeInvite :one
DELETE FROM invites
WHERE
  token_hash = @token_hash
  AND expires_at > NOW()
RETURNING
  email,
  role;

-- name: ListInvites :many
SELECT
  email,
  role,
  expires_at,
  created_at
FROM
  invites
WHERE
  expires_at > NOW()
ORDER BY
  created_at DESC;

-- name: DeleteInvite :execrows
DELETE FROM invites
WHERE
  email = @email;

-- name: DeleteExpiredInvites :execrows
DELETE FROM invites
WHERE
  expires_at < @now;
