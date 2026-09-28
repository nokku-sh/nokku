-- name: GetActorRole :one
-- The workspace role of a user or service account. Runs as the system role:
-- it resolves membership before any workspace is pinned.
SELECT
  wm.role_name
FROM
  workspace_members wm
WHERE
  wm.workspace_id = @workspace_id::UUID
  AND wm.user_id = @actor_id::UUID
UNION ALL
SELECT
  sa.role_name
FROM
  service_accounts sa
WHERE
  sa.workspace_id = @workspace_id::UUID
  AND sa.id = @actor_id::UUID
LIMIT
  1;

-- name: ListActorRoles :many
-- Every workspace role of a user or service account, keyed by workspace.
SELECT
  wm.workspace_id,
  wm.role_name
FROM
  workspace_members wm
WHERE
  wm.user_id = @actor_id::UUID
UNION ALL
SELECT
  sa.workspace_id,
  sa.role_name
FROM
  service_accounts sa
WHERE
  sa.id = @actor_id::UUID;
