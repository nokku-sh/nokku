-- name: CreateTeam :one
INSERT INTO
  teams (workspace_id, name, description, tags)
VALUES
  (@workspace_id, @name, @description, COALESCE(@tags, '{}'::TEXT[]))
RETURNING
  *;

-- name: GetTeam :one
SELECT
  *
FROM
  teams
WHERE
  id = @team_id;

-- name: ListTeams :many
SELECT
  *
FROM
  teams
WHERE
  workspace_id = @workspace_id
  AND (
    sqlc.narg('query')::TEXT IS NULL
    OR name ILIKE '%' || sqlc.narg('query') || '%'
    OR COALESCE(description, '') ILIKE '%' || sqlc.narg('query') || '%'
  )
  AND tags @> COALESCE(@tags, '{}'::TEXT[])
ORDER BY
  id ASC
LIMIT
  sqlc.narg('limit')
OFFSET
  sqlc.narg('offset');

-- name: CountTeams :one
SELECT
  COUNT(*)::INTEGER
FROM
  teams
WHERE
  workspace_id = @workspace_id
  AND (
    sqlc.narg('query')::TEXT IS NULL
    OR name ILIKE '%' || sqlc.narg('query') || '%'
    OR COALESCE(description, '') ILIKE '%' || sqlc.narg('query') || '%'
  )
  AND tags @> COALESCE(@tags, '{}'::TEXT[]);

-- name: UpdateTeam :one
UPDATE teams
SET
  name = COALESCE(sqlc.narg('name'), name),
  description = COALESCE(sqlc.narg('description'), description),
  tags = COALESCE(sqlc.narg('tags'), tags)
WHERE
  id = @team_id
RETURNING
  *;

-- name: DeleteTeam :one
DELETE FROM teams
WHERE
  id = @team_id
RETURNING
  *;

-- name: AddTeamMember :exec
INSERT INTO
  team_members (workspace_id, user_id, team_id)
SELECT
  t.workspace_id,
  @user_id,
  @team_id
FROM
  teams t
WHERE
  t.id = @team_id
ON CONFLICT (user_id, team_id) DO NOTHING;

-- name: RemoveTeamMember :exec
DELETE FROM team_members
WHERE
  team_id = @team_id
  AND user_id = @user_id;

-- name: ListTeamMembers :many
SELECT
  tm.workspace_id,
  tm.team_id,
  u.id,
  u.name,
  u.username,
  u.email,
  u.email_verified,
  u.picture,
  u.is_active,
  tm.created_at
FROM
  team_members tm
  JOIN users u ON u.id = tm.user_id
WHERE
  tm.team_id = @team_id;
