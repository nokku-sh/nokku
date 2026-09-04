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
