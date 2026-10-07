-- name: CreateSCIMToken :one
INSERT INTO
  scim_tokens (workspace_id, token_hash, label)
VALUES
  (@workspace_id, @token_hash, @label)
RETURNING
  id,
  label,
  created_at,
  last_used_at;

-- name: GetSCIMTokenByHash :one
SELECT
  *
FROM
  scim_tokens
WHERE
  workspace_id = @workspace_id
  AND token_hash = @token_hash;

-- name: TouchSCIMToken :exec
-- Only writes when the stamp is over an hour old.
UPDATE scim_tokens
SET
  last_used_at = NOW()
WHERE
  workspace_id = @workspace_id
  AND id = @id
  AND (
    last_used_at IS NULL
    OR last_used_at < NOW() - INTERVAL '1 hour'
  );

-- name: ListWorkspaceSCIMTokens :many
SELECT
  id,
  label,
  created_at,
  last_used_at
FROM
  scim_tokens
WHERE
  workspace_id = @workspace_id
ORDER BY
  created_at ASC;

-- name: DeleteSCIMToken :exec
DELETE FROM scim_tokens
WHERE
  workspace_id = @workspace_id
  AND id = @id;

-- name: ListSCIMUsers :many
SELECT
  sqlc.embed(u),
  COALESCE(c.subject, '')::TEXT AS external_id
FROM
  users u
  LEFT JOIN credentials c ON c.workspace_id = u.workspace_id
  AND c.user_id = u.id
  AND c.type = 'scim'
WHERE
  u.workspace_id = @workspace_id
  AND (
    sqlc.narg('user_id')::UUID IS NULL
    OR u.id = sqlc.narg('user_id')
  )
  AND (
    sqlc.narg('email')::TEXT IS NULL
    OR u.email = sqlc.narg('email')
  )
ORDER BY
  u.created_at ASC,
  u.id ASC;

-- name: DeleteUserSCIMCredentials :exec
DELETE FROM credentials
WHERE
  workspace_id = @workspace_id
  AND user_id = @user_id
  AND type = 'scim';

-- name: DeleteStaleUserSCIMCredentials :exec
-- Run before UpsertCredential so one account never carries two links.
DELETE FROM credentials
WHERE
  workspace_id = @workspace_id
  AND user_id = @user_id
  AND type = 'scim'
  AND subject <> @subject;
