-- name: CreateWorkspace :one
WITH
  new_workspace AS (
    INSERT INTO
      workspaces (name, description, created_by)
    VALUES
      (@name, @description, @created_by)
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
  new_oidc_provider AS (
    INSERT INTO
      oidc_providers (workspace_id)
    SELECT
      id
    FROM
      new_workspace
    RETURNING
      workspace_id
  ),
  new_saml_provider AS (
    INSERT INTO
      saml_providers (workspace_id)
    SELECT
      id
    FROM
      new_workspace
    RETURNING
      workspace_id
  ),
  new_settings AS (
    INSERT INTO
      workspace_settings (workspace_id)
    SELECT
      id
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
  sqlc.embed(w),
  sqlc.embed(ws)
FROM
  workspaces w
  LEFT JOIN workspace_settings ws ON ws.workspace_id = w.id
WHERE
  w.id = @workspace_id;

-- name: ListWorkspaces :many
SELECT
  sqlc.embed(w),
  sqlc.embed(ws)
FROM
  workspaces w
  LEFT JOIN workspace_settings ws ON ws.workspace_id = w.id
ORDER BY
  w.id ASC;

-- name: CountWorkspaces :one
SELECT
  COUNT(*)::INTEGER
FROM
  workspaces
  JOIN workspace_members wm ON wm.workspace_id = workspaces.id
WHERE
  wm.user_id = @user_id;

-- name: CountWorkspacesByOwner :one
SELECT
  COUNT(*)::INTEGER
FROM
  workspaces
WHERE
  created_by = @user_id;

-- name: GetWorkspacesByOwner :many
SELECT
  id
FROM
  workspaces
WHERE
  created_by = @user_id
ORDER BY
  id ASC;

-- name: GetUserWorkspaceIDs :many
SELECT
  workspace_id
FROM
  workspace_members
WHERE
  user_id = @user_id;

-- name: GetActorWorkspaceIDs :many
SELECT
  workspace_id
FROM
  workspace_members
WHERE
  user_id = @actor_id
UNION
SELECT
  workspace_id
  FROM
    daemons
  WHERE
    id = @actor_id
UNION
SELECT
  workspace_id
FROM
  service_accounts
WHERE
  id = @actor_id;

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
  u.id,
  u.name,
  u.username,
  u.email,
  u.email_verified,
  u.picture,
  u.is_active,
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
  u.id,
  u.name,
  u.username,
  u.email,
  u.email_verified,
  u.picture,
  u.is_active,
  wm.role_name,
  wm.created_at,
  wm.updated_at
FROM
  workspace_members wm
  JOIN users u ON u.id = wm.user_id
WHERE
  wm.workspace_id = @workspace_id
  AND (
    sqlc.narg('query')::TEXT IS NULL
    OR u.name ILIKE '%' || sqlc.narg('query') || '%'
    OR u.username ILIKE '%' || sqlc.narg('query') || '%'
    OR u.email ILIKE '%' || sqlc.narg('query') || '%'
  )
  AND (
    sqlc.narg('role_name')::TEXT IS NULL
    OR wm.role_name = sqlc.narg('role_name')::TEXT
  )
ORDER BY
  u.name ASC,
  u.username ASC
LIMIT
  sqlc.narg('limit')
OFFSET
  sqlc.narg('offset');

-- name: CountMembers :one
SELECT
  COUNT(*)::INTEGER
FROM
  workspace_members wm
  JOIN users u ON u.id = wm.user_id
WHERE
  wm.workspace_id = @workspace_id
  AND (
    sqlc.narg('query')::TEXT IS NULL
    OR u.name ILIKE '%' || sqlc.narg('query') || '%'
    OR u.username ILIKE '%' || sqlc.narg('query') || '%'
    OR u.email ILIKE '%' || sqlc.narg('query') || '%'
  )
  AND (
    sqlc.narg('role_name')::TEXT IS NULL
    OR wm.role_name = sqlc.narg('role_name')::TEXT
  );

-- name: UpdateWorkspace :one
UPDATE workspaces
SET
  name = COALESCE(sqlc.narg('name'), name),
  description = COALESCE(sqlc.narg('description'), description)
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

-- name: DeleteWorkspacesByOwner :exec
DELETE FROM workspaces
WHERE
  created_by = @user_id;

-- name: AddWorkspaceMember :exec
INSERT INTO
  workspace_members (workspace_id, user_id, role_name)
VALUES
  (@workspace_id, @user_id, 'member')
ON CONFLICT (workspace_id, user_id) DO NOTHING;

-- name: RemoveWorkspaceMember :execrows
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
WITH
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
      role_name = 'member'
    FROM
      old_owner
    WHERE
      workspace_members.workspace_id = @workspace_id
      AND workspace_members.user_id = old_owner.created_by
  ),
  update_new_owner AS (
    UPDATE workspace_members
    SET
      role_name = 'owner'
    WHERE
      workspace_members.workspace_id = @workspace_id
      AND workspace_members.user_id = @new_owner_id
  )
UPDATE workspaces
SET
  created_by = @new_owner_id
WHERE
  workspaces.id = @workspace_id
RETURNING
  *;

---- Workspace Settings -------------------------------------------------------\
-- name: GetWorkspaceSettings :one
SELECT
  *
FROM
  workspace_settings
WHERE
  workspace_id = @workspace_id;

-- name: UpdateWorkspaceSettings :one
UPDATE workspace_settings
SET
  enroll_token_hash = COALESCE(sqlc.narg('enroll_token_hash'), enroll_token_hash),
  enroll_expires_at = COALESCE(sqlc.narg('enroll_expires_at'), enroll_expires_at),
  enroll_auto_approve = COALESCE(sqlc.narg('enroll_auto_approve'), enroll_auto_approve),
  invite_token_hash = COALESCE(sqlc.narg('invite_token_hash'), invite_token_hash),
  invite_expires_at = COALESCE(sqlc.narg('invite_expires_at'), invite_expires_at)
WHERE
  workspace_id = @workspace_id
RETURNING
  *;
