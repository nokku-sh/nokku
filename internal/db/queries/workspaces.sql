-- name: CreateWorkspace :one
INSERT INTO
  workspaces (id, slug, name, description, settings)
VALUES
  (@id, @slug, @name, sqlc.narg('description'), @settings)
RETURNING
  *;

-- name: InitSubscription :exec
INSERT INTO
  workspace_subscriptions DEFAULT
VALUES
ON CONFLICT (workspace_id) DO NOTHING;

-- name: GetWorkspace :one
-- The workspace the transaction is pinned to.
SELECT
  *
FROM
  workspaces
WHERE
  id = current_workspace_id ();

-- name: GetWorkspaceForUpdate :one
SELECT
  *
FROM
  workspaces
WHERE
  id = current_workspace_id ()
FOR UPDATE;

-- name: GetWorkspaceBySlug :one
SELECT
  *
FROM
  workspaces
WHERE
  slug = @slug;

-- name: GetFirstWorkspace :one
-- The one workspace of a self-hosted server.
SELECT
  *
FROM
  workspaces
ORDER BY
  created_at ASC,
  id ASC
LIMIT
  1;

-- name: ListUnclaimedWorkspaces :many
-- Signups whose owner never signed in. Runs as nokku_system.
SELECT
  w.*
FROM
  workspaces w
WHERE
  w.created_at < @cutoff
  AND NOT EXISTS (
    SELECT
      1
    FROM
      sessions s
    WHERE
      s.workspace_id = w.id
  )
  AND NOT EXISTS (
    SELECT
      1
    FROM
      credentials c
    WHERE
      c.workspace_id = w.id
  )
  AND NOT EXISTS (
    SELECT
      1
    FROM
      known_devices d
    WHERE
      d.workspace_id = w.id
  );

-- name: UpdateWorkspace :one
UPDATE workspaces
SET
  name = COALESCE(sqlc.narg('name'), name),
  description = COALESCE(sqlc.narg('description'), description),
  settings = @settings,
  updated_at = NOW()
WHERE
  id = current_workspace_id ()
RETURNING
  *;

-- name: DeleteWorkspace :exec
-- Names the workspace, the purge of unclaimed signups runs as nokku_system.
DELETE FROM workspaces
WHERE
  id = @workspace_id;

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
