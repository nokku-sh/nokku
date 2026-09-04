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

-- name: CountOtherUserMemberships :one
-- Memberships the user holds in workspaces they did not create, outside
-- the given workspace. SCIM deprovision keys off this: a membership in
-- someone else's workspace keeps the global account alive, while ties
-- only to the user's own workspaces are the shadow-IT orphan that gets
-- deactivated instead of deleted (the created_by cascade must never fire).
SELECT
  COUNT(*)::INTEGER
FROM
  workspace_members wm
WHERE
  wm.user_id = @user_id
  AND wm.workspace_id <> @workspace_id
  AND NOT EXISTS (
    SELECT
      1
    FROM
      workspaces w
    WHERE
      w.id = wm.workspace_id
      AND w.created_by = wm.user_id
  );

-- name: DeleteUserSCIMCredentials :exec
DELETE FROM credentials
WHERE
  user_id = @user_id
  AND type = 'scim'
  AND provider = @workspace_id;

-- name: ListWorkspaceSCIMCredentials :many
-- externalId mappings for every SCIM-linked user of the workspace, one read
-- for list responses instead of one per resource.
SELECT
  user_id,
  subject
FROM
  credentials
WHERE
  type = 'scim'
  AND provider = @workspace_id
  AND subject <> '';

-- name: GetSCIMCredentialByUser :one
SELECT
  subject
FROM
  credentials
WHERE
  user_id = @user_id
  AND type = 'scim'
  AND provider = @workspace_id
  AND subject <> ''
LIMIT
  1;

-- name: CountWorkspacesCreatedBy :one
-- Workspaces the user owns. A SCIM deprovision must never delete a global
-- account that owns a workspace: the schema's created_by cascade would take
-- the whole workspace with it.
SELECT
  COUNT(*)::INTEGER
FROM
  workspaces
WHERE
  created_by = @user_id;

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
