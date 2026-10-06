-- name: CreateWorkspace :one
WITH
  new_workspace AS (
    INSERT INTO
      workspaces (name, description, settings, created_by)
    VALUES
      (@name, @description, COALESCE(@settings, '{}'::jsonb), @created_by)
    RETURNING
      *
  ),
  new_member AS (
    INSERT INTO
      workspace_members (workspace_id, user_id, role_name)
    SELECT
      id,
      created_by,
      'owner'
    FROM
      new_workspace
    RETURNING
      workspace_id
  ),
  new_subscription AS (
    INSERT INTO
      workspace_subscriptions (workspace_id)
    SELECT
      id
    FROM
      new_workspace
    RETURNING
      workspace_id
  )
SELECT
  new_workspace.*
FROM
  new_workspace;

-- name: GetWorkspace :one
SELECT
  *
FROM
  workspaces w
WHERE
  w.id = @workspace_id;

-- name: GetWorkspaceForUpdate :one
SELECT
  *
FROM
  workspaces w
WHERE
  w.id = @workspace_id
FOR UPDATE;

-- name: GetWorkspacesByIDs :many
SELECT
  *
FROM
  workspaces w
WHERE
  w.id = ANY (sqlc.arg('workspace_ids')::UUID[])
ORDER BY
  w.id;

-- name: ListWorkspaces :many
SELECT
  *
FROM
  workspaces
ORDER BY
  id ASC;

-- name: CountWorkspacesByOwner :one
SELECT
  COUNT(*)::INTEGER
FROM
  workspaces
WHERE
  created_by = @user_id;

-- name: ListOwnedWorkspaces :many
SELECT
  w.id,
  w.name,
  (
    SELECT
      COUNT(*)
    FROM
      workspace_members wm
    WHERE
      wm.workspace_id = w.id
  )::INTEGER AS member_count
FROM
  workspaces w
WHERE
  w.created_by = @user_id
ORDER BY
  w.name ASC;

-- name: GetActorWorkspaceIDs :many
SELECT
  workspace_id
FROM
  workspace_members
WHERE
  user_id = @actor_id::uuid
UNION
SELECT
  workspace_id
FROM
  daemons
WHERE
  id = @actor_id::uuid
UNION
SELECT
  workspace_id
FROM
  service_accounts
WHERE
  id = @actor_id::uuid;

-- name: UserWorkspaceMember :one
SELECT
  TRUE
FROM
  workspace_members
WHERE
  workspace_id = @workspace_id
  AND user_id = @user_id;

-- name: GetWorkspaceMember :one
SELECT
  wm.workspace_id,
  u.id AS user_id,
  u.name,
  u.email,
  u.email_verified,
  u.picture,
  wm.role_name,
  wm.created_at,
  wm.updated_at
FROM
  workspace_members wm
  JOIN users u ON u.id = wm.user_id
WHERE
  wm.workspace_id = @workspace_id
  AND wm.user_id = @user_id;

-- name: ListWorkspaceMembers :many
SELECT
  wm.workspace_id,
  u.id AS user_id,
  u.name,
  u.email,
  u.email_verified,
  u.picture,
  u.active,
  wm.role_name,
  wm.created_at,
  wm.updated_at,
  COUNT(*) OVER ()::INTEGER AS total_count
FROM
  workspace_members wm
  JOIN users u ON u.id = wm.user_id
WHERE
  wm.workspace_id = @workspace_id
  AND (
    sqlc.narg('query')::TEXT IS NULL
    OR u.name ILIKE '%' || sqlc.narg('query') || '%'
    OR u.email ILIKE '%' || sqlc.narg('query') || '%'
  )
  AND (
    sqlc.narg('role_name')::TEXT IS NULL
    OR wm.role_name = sqlc.narg('role_name')::TEXT
  )
ORDER BY
  u.name ASC,
  u.email ASC
LIMIT
  sqlc.narg('limit')
OFFSET
  sqlc.narg('offset');

-- name: UpdateWorkspace :one
UPDATE workspaces
SET
  name = COALESCE(sqlc.narg('name'), name),
  description = COALESCE(sqlc.narg('description'), description),
  settings = @settings
WHERE
  id = @workspace_id
RETURNING
  *;

-- name: GetWorkspaceOwner :one
SELECT
  created_by
FROM
  workspaces
WHERE
  id = @workspace_id;

-- name: DeleteWorkspace :exec
DELETE FROM workspaces
WHERE
  id = @workspace_id;

-- name: RemoveWorkspaceMember :exec
DELETE FROM workspace_members wm USING workspaces w
WHERE
  wm.workspace_id = w.id
  AND wm.workspace_id = @workspace_id
  AND wm.user_id = @user_id
  AND wm.user_id <> w.created_by;

-- name: UpdateWorkspaceMember :exec
UPDATE workspace_members
SET
  role_name = COALESCE(@role_name, role_name)
WHERE
  workspace_id = @workspace_id
  AND user_id = @user_id;

-- name: UpdateWorkspaceOwner :one
-- Only a member can take over. Every statement joins new_owner, so anyone
-- else changes nothing and gets no row.
WITH
  new_owner AS (
    SELECT
      wm.user_id
    FROM
      workspace_members wm
    WHERE
      wm.workspace_id = @workspace_id
      AND wm.user_id = @new_owner_id
  ),
  old_owner AS (
    SELECT
      created_by
    FROM
      workspaces
    WHERE
      id = @workspace_id
  ),
  update_old_owner AS (
    UPDATE workspace_members
    SET
      role_name = 'admin'
    FROM
      old_owner,
      new_owner
    WHERE
      workspace_members.workspace_id = @workspace_id
      AND workspace_members.user_id = old_owner.created_by
  ),
  update_new_owner AS (
    UPDATE workspace_members
    SET
      role_name = 'owner'
    FROM
      new_owner
    WHERE
      workspace_members.workspace_id = @workspace_id
      AND workspace_members.user_id = new_owner.user_id
  )
UPDATE workspaces
SET
  created_by = new_owner.user_id
FROM
  new_owner
WHERE
  workspaces.id = @workspace_id
RETURNING
  workspaces.*;

-- name: EnsureWorkspaceMember :exec
INSERT INTO
  workspace_members (workspace_id, user_id, role_name)
VALUES
  (@workspace_id, @user_id, @role_name)
ON CONFLICT (workspace_id, user_id) DO NOTHING;

-- name: ListWorkspaceAuditWebhooks :many
-- Cross-tenant read, must run as nokku_system.
SELECT
  id,
  (settings ->> 'audit_webhook_url')::text AS webhook_url,
  (settings ->> 'audit_webhook_secret')::text AS webhook_secret
FROM workspaces
WHERE
  coalesce(settings ->> 'audit_webhook_url', '') <> '';

-- name: GetWorkspaceStateVersion :one
SELECT
  version
FROM
  workspace_state
WHERE
  workspace_id = @workspace_id;
