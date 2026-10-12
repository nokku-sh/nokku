-- name: PutToken :exec
INSERT INTO
  one_time_tokens (token_hash, user_id, purpose, expires_at, email)
VALUES
  (@token_hash, @user_id, @purpose, @expires_at, sqlc.narg('email'));

-- name: PutSignupToken :exec
INSERT INTO
  one_time_tokens (token_hash, purpose, expires_at, email, data)
VALUES
  (@token_hash, 'signup', @expires_at, @email, @data);

-- name: ConsumeToken :one
-- Spends a token of a user. A signup token has none, see ConsumeSignupToken.
DELETE FROM one_time_tokens
WHERE
  token_hash = @token_hash
  AND purpose = @purpose
  AND user_id IS NOT NULL
  AND expires_at > NOW()
RETURNING
  user_id::UUID AS user_id;

-- name: ConsumeSignupToken :one
DELETE FROM one_time_tokens
WHERE
  token_hash = @token_hash
  AND purpose = 'signup'
  AND expires_at > NOW()
RETURNING
  email::TEXT AS email,
  data;

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
