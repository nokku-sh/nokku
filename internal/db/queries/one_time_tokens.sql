-- One-time tokens (email verification, password reset) ------------------------
-- name: CreateOneTimeToken :exec
INSERT INTO
  one_time_tokens (token_hash, user_id, purpose, expires_at)
VALUES
  (@token_hash, @user_id, @purpose, @expires_at);

-- name: ConsumeOneTimeToken :one
DELETE FROM one_time_tokens
WHERE
  token_hash = @token_hash
  AND expires_at > NOW()
RETURNING
  user_id,
  purpose;

-- name: DeleteExpiredOneTimeTokens :exec
DELETE FROM one_time_tokens
WHERE
  expires_at <= NOW();
