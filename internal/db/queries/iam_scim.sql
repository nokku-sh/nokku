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
  token_hash = @token_hash;

-- name: TouchSCIMToken :exec
-- Throttled: only writes when the stored stamp is over an hour old, so a
-- busy provisioning client does not turn every read into a write.
UPDATE scim_tokens
SET
  last_used_at = NOW()
WHERE
  id = @id
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
  id = @id
  AND workspace_id = @workspace_id;

-- name: CountUserMemberships :one
SELECT
  COUNT(*)::INTEGER
FROM
  workspace_members
WHERE
  user_id = @user_id;

-- name: ListManagedMembers :many
-- Members whose email domain the workspace has verified: the only accounts
-- a SCIM connector may see or change. email narrows to one account.
SELECT
  u.*,
  COALESCE(c.subject, '')::TEXT AS external_id
FROM
  workspace_members wm
  JOIN users u ON u.id = wm.user_id
  JOIN workspace_domains d ON d.workspace_id = wm.workspace_id
  AND d.domain = split_part(u.email, '@', 2)
  AND d.verified_at IS NOT NULL
  LEFT JOIN credentials c ON c.user_id = u.id
  AND c.type = 'scim'
  AND c.provider = wm.workspace_id::TEXT
WHERE
  wm.workspace_id = @workspace_id
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
  user_id = @user_id
  AND type = 'scim'
  AND provider = @workspace_id;

-- name: DeleteStaleUserSCIMCredentials :exec
-- Drops the user's other SCIM externalId mappings for the workspace, so an
-- IdP-side identity migration never leaves two links on one account. Run
-- before UpsertCredential, which re-adds the current subject.
DELETE FROM credentials
WHERE
  user_id = @user_id
  AND type = 'scim'
  AND provider = @workspace_id
  AND subject <> @subject;
