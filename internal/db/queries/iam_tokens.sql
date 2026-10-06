-- name: PutToken :exec
INSERT INTO
  one_time_tokens (token_hash, user_id, purpose, expires_at, email)
VALUES
  (@token_hash, @user_id, @purpose, @expires_at, sqlc.narg('email'));

-- name: ConsumeToken :one
DELETE FROM one_time_tokens
WHERE
  token_hash = @token_hash
  AND purpose = @purpose
  AND expires_at > NOW()
RETURNING
  user_id;

-- name: GetTokenUser :one
-- Reads a token without spending it.
SELECT
  user_id
FROM
  one_time_tokens
WHERE
  token_hash = @token_hash
  AND purpose = @purpose
  AND expires_at > NOW();

-- name: ConsumeEmailToken :one
DELETE FROM one_time_tokens
WHERE
  token_hash = @token_hash
  AND purpose = @purpose
  AND expires_at > NOW()
  AND email IS NOT NULL
RETURNING
  user_id,
  email;

-- name: DeleteUserTokens :exec
DELETE FROM one_time_tokens
WHERE
  user_id = @user_id
  AND purpose = @purpose;

-- name: GetPendingTokenEmail :one
SELECT
  email
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

-- name: HasRecentToken :one
SELECT EXISTS (
  SELECT 1
  FROM one_time_tokens
  WHERE
    user_id = @user_id
    AND purpose = @purpose
    AND created_at > @since
);

-- name: DeleteExpiredTokens :execrows
DELETE FROM one_time_tokens
WHERE
  expires_at < @now;
