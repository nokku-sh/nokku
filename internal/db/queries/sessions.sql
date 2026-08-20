-- Sessions -------------------------------------------------------------------
-- name: CreateSession :exec
INSERT INTO
  sessions (
    token_hash,
    tenant_id,
    subject_id,
    kind,
    identity_id,
    method,
    binding,
    expires_at
  )
VALUES
  (
    @token_hash,
    @tenant_id,
    @subject_id,
    @kind,
    sqlc.narg('identity_id'),
    @method,
    sqlc.narg('binding'),
    sqlc.narg('expires_at')
  );

-- name: GetSessionByHash :one
SELECT
  *
FROM
  sessions
WHERE
  token_hash = @token_hash;

-- name: TouchSession :exec
UPDATE sessions
SET
  last_seen = NOW()
WHERE
  token_hash = @token_hash;

-- name: ListSessionsBySubject :many
SELECT
  *
FROM
  sessions
WHERE
  tenant_id = @tenant_id
  AND subject_id = @subject_id;

-- name: DeleteSessionByHash :exec
DELETE FROM sessions
WHERE
  token_hash = @token_hash;

-- name: DeleteSessionForSubject :exec
DELETE FROM sessions
WHERE
  token_hash = @token_hash
  AND subject_id = @subject_id;

-- name: DeleteSubjectSessions :exec
DELETE FROM sessions
WHERE
  tenant_id = @tenant_id
  AND subject_id = @subject_id;

-- name: DeleteIdentitySessions :exec
DELETE FROM sessions
WHERE
  identity_id = @identity_id;
