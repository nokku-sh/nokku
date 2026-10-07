-- name: CreateSession :one
INSERT INTO
  sessions (
    token_hash,
    subject_id,
    user_id,
    kind,
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
    @subject_id::TEXT,
    CASE
      WHEN @kind::TEXT <> 'daemon' THEN (@subject_id::TEXT)::UUID
    END,
    @kind::TEXT,
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

-- name: GetSession :one
SELECT
  *
FROM
  sessions
WHERE
  token_hash = @token_hash;

-- name: ListSessionsBySubject :many
SELECT
  *
FROM
  sessions
WHERE
  subject_id = @subject_id
ORDER BY
  last_seen_at DESC NULLS LAST;

-- name: TouchSession :exec
UPDATE sessions
SET
  last_seen_at = @last_seen_at
WHERE
  token_hash = @token_hash;

-- name: DeleteSession :exec
DELETE FROM sessions
WHERE
  token_hash = @token_hash;

-- name: DeleteSubjectSessions :execrows
-- Signs the subject out everywhere. A user's devices are forgotten with it,
-- so whoever got in from one of them is not waved through quietly again.
WITH
  forgotten AS (
    DELETE FROM known_devices
    WHERE
      user_id::TEXT = @subject_id::TEXT
  )
DELETE FROM sessions
WHERE
  subject_id = @subject_id::TEXT;

-- name: DeleteSessionsExcept :execrows
DELETE FROM sessions
WHERE
  subject_id = @subject_id
  AND token_hash <> @keep_hash;

-- name: DeleteExpiredSessions :execrows
-- Every tenant, runs as nokku_system.
DELETE FROM sessions
WHERE
  expires_at IS NOT NULL
  AND expires_at < @now;
