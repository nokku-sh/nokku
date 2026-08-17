-- One-time tokens (email verification, password reset) ------------------------
-- name: CreateOneTimeToken :exec
INSERT INTO
  one_time_tokens (token_hash, user_id, purpose, expires_at)
VALUES
  (@token_hash, @user_id, @purpose, @expires_at);

-- name: GetOneTimeToken :one
SELECT
  *
FROM
  one_time_tokens
WHERE
  token_hash = @token_hash;

-- name: DeleteOneTimeToken :exec
DELETE FROM one_time_tokens
WHERE
  token_hash = @token_hash;

-- name: DeleteExpiredOneTimeTokens :exec
DELETE FROM one_time_tokens
WHERE
  expires_at <= NOW();
