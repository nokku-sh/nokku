-- name: PutToken :exec
INSERT INTO
  one_time_tokens (token_hash, user_id, purpose, expires_at)
VALUES
  (@token_hash, @user_id, @purpose, @expires_at);

-- name: ConsumeToken :one
DELETE FROM one_time_tokens
WHERE
  token_hash = @token_hash
  AND expires_at > NOW()
RETURNING
  user_id,
  purpose;

-- name: DeleteExpiredTokens :execrows
DELETE FROM one_time_tokens
WHERE
  expires_at < @now;
