-- name: CreateAccessToken :one
-- One subject parameter, the column it lands in follows the kind. A SCIM
-- token has no subject.
INSERT INTO
  access_tokens (
    token_hash,
    kind,
    user_id,
    service_account_id,
    daemon_id,
    method,
    binding,
    label,
    user_agent,
    ip,
    expires_at,
    last_seen_at
  )
VALUES
  (
    @token_hash,
    @kind::TEXT,
    CASE
      WHEN @kind::TEXT IN ('user', 'cli') THEN sqlc.narg('subject_id')::UUID
    END,
    CASE
      WHEN @kind::TEXT = 'service_account' THEN sqlc.narg('subject_id')::UUID
    END,
    CASE
      WHEN @kind::TEXT = 'daemon' THEN sqlc.narg('subject_id')::UUID
    END,
    @method,
    @binding,
    @label,
    @user_agent,
    @ip,
    sqlc.narg('expires_at'),
    sqlc.narg('last_seen_at')
  )
RETURNING
  *;

-- name: GetAccessToken :one
SELECT
  *
FROM
  access_tokens
WHERE
  token_hash = @token_hash;

-- name: TouchAccessToken :exec
UPDATE access_tokens
SET
  last_seen_at = @last_seen_at
WHERE
  id = @id;

-- name: DeleteAccessToken :exec
DELETE FROM access_tokens
WHERE
  id = @id;

-- name: DeleteSubjectTokens :execrows
-- Signs the subject out everywhere. A user's devices are forgotten with it,
-- so whoever got in from one of them is not waved through quietly again.
WITH
  forgotten AS (
    DELETE FROM known_devices
    WHERE
      user_id = @subject_id::UUID
  )
DELETE FROM access_tokens
WHERE
  subject_id = @subject_id::UUID;

-- name: ListUserSessions :many
-- The browsers and terminals one user is signed in from.
SELECT
  *
FROM
  access_tokens
WHERE
  user_id = @user_id::UUID
ORDER BY
  last_seen_at DESC NULLS LAST;

-- name: DeleteExpiredAccessTokens :execrows
-- Every tenant, runs as nokku_system.
DELETE FROM access_tokens
WHERE
  expires_at IS NOT NULL
  AND expires_at < @now;

-- name: ListServiceAccountTokens :many
SELECT
  *
FROM
  access_tokens
WHERE
  service_account_id = @service_account_id::UUID
ORDER BY
  created_at DESC;

-- name: DeleteServiceAccountToken :execrows
DELETE FROM access_tokens
WHERE
  id = @id
  AND service_account_id = @service_account_id::UUID;

-- name: ListSCIMTokens :many
SELECT
  *
FROM
  access_tokens
WHERE
  kind = 'scim'
ORDER BY
  created_at ASC;

-- name: DeleteSCIMToken :exec
DELETE FROM access_tokens
WHERE
  id = @id
  AND kind = 'scim';
