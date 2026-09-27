-- name: EnsureRole :exec
INSERT INTO
  roles (name, description)
VALUES
  (@name, @description)
ON CONFLICT (name) DO NOTHING;

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
