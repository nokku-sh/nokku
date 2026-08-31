-- name: CreateSession :exec
INSERT INTO
  sessions (token_hash, subject_id, kind, method, workspace_id, binding, label, expires_at)
VALUES
  (
    @token_hash,
    @subject_id,
    @kind,
    @method,
    sqlc.narg('workspace_id'),
    @binding,
    @label,
    sqlc.narg('expires_at')
  );

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
  last_seen_at DESC;

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
DELETE FROM sessions
WHERE
  subject_id = @subject_id;

-- name: DeleteSessionsExcept :execrows
DELETE FROM sessions
WHERE
  subject_id = @subject_id
  AND token_hash <> @keep_hash;

-- name: DeleteExpiredSessions :execrows
DELETE FROM sessions
WHERE
  expires_at IS NOT NULL
  AND expires_at < @now;
