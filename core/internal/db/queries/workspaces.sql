-- name: CreateWorkspace :one
INSERT INTO
  workspaces (id, slug, name, description, settings)
VALUES
  (@id, @slug, @name, sqlc.narg('description'), @settings)
RETURNING
  *;

-- name: StartTrial :exec
-- A hosted workspace starts on a trial, the first checkout replaces the row. Its status is none of Stripe's, so
-- entitlement.Active never reads it as paid.
INSERT INTO
  workspace_subscriptions (source, plan, status, current_period_end)
VALUES
  (
    'trial',
    @plan,
    'trial',
    NOW() + make_interval(days => @days::int)
  )
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
-- Signups nobody ever signed in to. Runs as nokku_system.
SELECT
  *
FROM
  workspaces
WHERE
  created_at < @cutoff
  AND claimed_at IS NULL;

-- name: DeleteUnclaimedWorkspace :execrows
-- Asks again, a first sign-in may have come since the list.
DELETE FROM workspaces
WHERE
  id = @workspace_id
  AND claimed_at IS NULL;

-- name: ClaimWorkspace :exec
-- Stored once, the sessions and devices of a first sign-in all end or get deleted.
UPDATE workspaces
SET
  claimed_at = NOW()
WHERE
  claimed_at IS NULL;

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

-- name: GetWorkspaceStateVersion :one
SELECT
  version
FROM
  workspace_state
WHERE
  workspace_id = @workspace_id;
