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
  sqlc.embed(te),
  COUNT(*) OVER ()::INTEGER AS total_count
FROM
  teams te
WHERE
  te.workspace_id = @workspace_id
  AND (
    sqlc.narg('query')::TEXT IS NULL
    OR te.name ILIKE '%' || sqlc.narg('query') || '%'
    OR COALESCE(te.description, '') ILIKE '%' || sqlc.narg('query') || '%'
  )
  AND te.tags @> COALESCE(sqlc.narg('tags'), '{}'::TEXT[])
ORDER BY
  te.id ASC
LIMIT
  sqlc.narg('limit')
OFFSET
  sqlc.narg('offset');

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
  sqlc.embed(u),
  tm.team_id
FROM
  team_members tm
  JOIN users u ON u.workspace_id = tm.workspace_id
  AND u.id = tm.user_id
WHERE
  tm.team_id = @team_id
ORDER BY
  u.name ASC,
  u.email ASC;

-- name: CountTeamMembers :many
SELECT
  tm.team_id,
  COUNT(*)::INTEGER AS member_count
FROM
  team_members tm
WHERE
  tm.team_id = ANY (@team_ids::UUID[])
GROUP BY
  tm.team_id;

-- name: ListTeamsForUser :many
SELECT
  t.*
FROM
  teams t
  JOIN team_members tm ON tm.team_id = t.id
WHERE
  tm.workspace_id = @workspace_id
  AND tm.user_id = @user_id
ORDER BY
  t.id ASC;
