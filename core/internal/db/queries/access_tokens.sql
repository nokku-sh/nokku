-- name: CreateAccessToken :one
INSERT INTO
  access_tokens (
    token_hash,
    kind,
    user_id,
    service_account_id,
    daemon_id,
    method,
    dpop_thumbprint,
    ssh_key,
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
    @dpop_thumbprint,
    @ssh_key,
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
-- Drops a pending nk login too, or an old approval still becomes a token.
WITH
  forgotten AS (
    DELETE FROM known_devices
    WHERE
      user_id = @subject_id::UUID
  ),
  pending AS (
    DELETE FROM device_grants
    WHERE
      decided_by = @subject_id::UUID
  )
DELETE FROM access_tokens
WHERE
  subject_id = @subject_id::UUID;

-- name: ListUserSessions :many
SELECT
  *
FROM
  access_tokens
WHERE
  user_id = @user_id::UUID
ORDER BY
  last_seen_at DESC NULLS LAST;

-- name: DeleteExpiredAccessTokens :execrows
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

-- name: SpendJobToken :exec
-- A job token works once, a second use trips the primary key.
INSERT INTO
  spent_job_tokens (issuer, jti, expires_at)
VALUES
  (@issuer, @jti, @expires_at);

-- name: DeleteExpiredSpentJobTokens :execrows
DELETE FROM spent_job_tokens
WHERE
  expires_at < @now;

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

-- name: CapSessions :execrows
UPDATE access_tokens
SET
  expires_at = @not_after::TIMESTAMPTZ
WHERE
  kind IN ('user', 'cli')
  AND (
    expires_at IS NULL
    OR expires_at > @not_after::TIMESTAMPTZ
  );

-- name: DeleteNonSSOSessions :execrows
-- The owner keeps theirs, the way in when a provider breaks.
DELETE FROM access_tokens
WHERE
  kind IN ('user', 'cli')
  AND method <> 'oidc'
  AND user_id NOT IN (
    SELECT
      id
    FROM
      users
    WHERE
      role = 5
  );
