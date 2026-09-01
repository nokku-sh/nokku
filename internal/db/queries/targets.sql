-- name: CreateTarget :one
INSERT INTO
  targets (workspace_id, ca_id, name, description, endpoints, tags, metadata)
VALUES
  (
    @workspace_id,
    @ca_id,
    @name,
    @description,
    @endpoints,
    COALESCE(@tags, '{}'::TEXT[]),
    COALESCE(@metadata, '{}'::JSONB)
  )
RETURNING
  *;

-- name: GetTarget :one
SELECT
  *
FROM
  targets
WHERE
  id = @target_id;

-- name: ListTargets :many
SELECT
  t.*,
  COUNT(*) OVER ()::INTEGER AS total_count
FROM
  targets t
WHERE
  t.workspace_id = @workspace_id
  AND (
    sqlc.narg('query')::TEXT IS NULL
    OR t.name ILIKE '%' || sqlc.narg('query') || '%'
    OR COALESCE(t.description, '') ILIKE '%' || sqlc.narg('query') || '%'
  )
  AND (
    sqlc.narg('daemon_id')::UUID IS NULL
    OR t.daemon_id = sqlc.narg('daemon_id')::UUID
  )
  AND (
    sqlc.narg('ca_id')::UUID IS NULL
    OR t.ca_id = sqlc.narg('ca_id')::UUID
  )
  AND (
    sqlc.narg('principals')::TEXT[] IS NULL
    OR EXISTS (
      SELECT
        1
      FROM
        principals p
      WHERE
        p.target_id = t.id
        AND p.username = ANY (sqlc.narg('principals')::TEXT[])
    )
  )
  AND (
    sqlc.narg('tags')::TEXT[] IS NULL
    OR t.tags @> COALESCE(sqlc.narg('tags'), '{}'::TEXT[])
  )
ORDER BY
  t.id ASC
LIMIT
  sqlc.narg('limit')
OFFSET
  sqlc.narg('offset');

-- name: UpdateTarget :one
UPDATE targets
SET
  ca_id = COALESCE(sqlc.narg('ca_id'), ca_id),
  name = COALESCE(sqlc.narg('name'), name),
  description = COALESCE(sqlc.narg('description'), description),
  endpoints = COALESCE(sqlc.narg('endpoints'), endpoints),
  tags = COALESCE(sqlc.narg('tags'), tags),
  metadata = COALESCE(sqlc.narg('metadata'), metadata)
WHERE
  id = @target_id
RETURNING
  *;

-- name: DeleteTarget :one
DELETE FROM targets
WHERE
  id = @target_id
RETURNING
  *;

-- name: UpdateTargetCA :one
UPDATE targets
SET
  ca_id = COALESCE(
    sqlc.narg('ca_id'),
    (
      SELECT
        id
      FROM
        certificate_authorities
      WHERE
        workspace_id = targets.workspace_id
        AND is_default = TRUE
      LIMIT
        1
    )
  )
WHERE
  targets.daemon_id = @daemon_id
RETURNING
  *;

-- name: GetTargetsBySubject :many
-- Returns every target a subject can reach. A subject is a user, a team, or a
-- service account, all identified by their UUID. For a user, access granted to
-- any of their teams is also included (via team_members).
SELECT DISTINCT
  t.*
FROM
  targets t
WHERE
  t.daemon_id = sqlc.arg('subject_id')::UUID
  OR EXISTS (
    SELECT
      1
    FROM
      principals p
    WHERE
      p.target_id = t.id
      AND (
        -- Direct user grant
        EXISTS (
          SELECT
            1
          FROM
            principal_users pu
          WHERE
            pu.principal_id = p.id
            AND pu.user_id = sqlc.arg('subject_id')::UUID
        )
        -- Subject is a team with a direct grant
        OR EXISTS (
          SELECT
            1
          FROM
            principal_teams pt
          WHERE
            pt.principal_id = p.id
            AND pt.team_id = sqlc.arg('subject_id')::UUID
        )
        -- Subject is a service account with a direct grant
        OR EXISTS (
          SELECT
            1
          FROM
            principal_service_accounts psa
          WHERE
            psa.principal_id = p.id
            AND psa.service_account_id = sqlc.arg('subject_id')::UUID
        )
        -- Subject is a user who belongs to a team granted access
        OR EXISTS (
          SELECT
            1
          FROM
            principal_teams granted_team
            JOIN team_members tm ON tm.team_id = granted_team.team_id
          WHERE
            granted_team.principal_id = p.id
            AND tm.user_id = sqlc.arg('subject_id')::UUID
        )
      )
  );

-- name: GetSubjectTargetsByWorkspaces :many
-- Returns every target a subject can reach within an explicit workspace set.
-- Grant logic is identical to GetTargetsBySubject (direct user grants, team
-- grants, service-account grants, and team membership for users); the
-- workspace set constrains the result so a caller can never read beyond its
-- current memberships, even if a stale grant lingers elsewhere.
SELECT DISTINCT
  t.*
FROM
  targets t
WHERE
  t.workspace_id = ANY (sqlc.arg('workspace_ids')::UUID[])
  AND (
    t.daemon_id = sqlc.arg('subject_id')::UUID
    OR EXISTS (
      SELECT
        1
      FROM
        principals p
      WHERE
        p.target_id = t.id
        AND (
          -- Direct user grant
          EXISTS (
            SELECT
              1
            FROM
              principal_users pu
            WHERE
              pu.principal_id = p.id
              AND pu.user_id = sqlc.arg('subject_id')::UUID
          )
          -- Subject is a team with a direct grant
          OR EXISTS (
            SELECT
              1
            FROM
              principal_teams pt
            WHERE
              pt.principal_id = p.id
              AND pt.team_id = sqlc.arg('subject_id')::UUID
          )
          -- Subject is a service account with a direct grant
          OR EXISTS (
            SELECT
              1
            FROM
              principal_service_accounts psa
            WHERE
              psa.principal_id = p.id
              AND psa.service_account_id = sqlc.arg('subject_id')::UUID
          )
          -- Subject is a user who belongs to a team granted access
          OR EXISTS (
            SELECT
              1
            FROM
              principal_teams granted_team
              JOIN team_members tm ON tm.team_id = granted_team.team_id
            WHERE
              granted_team.principal_id = p.id
              AND tm.user_id = sqlc.arg('subject_id')::UUID
          )
        )
    )
  )
ORDER BY
  t.workspace_id,
  t.name;

-- name: GetWorkspaceTags :many
SELECT DISTINCT
  unnest(tags)::TEXT AS tag
FROM
  targets
WHERE
  workspace_id = @workspace_id
ORDER BY
  tag ASC;

-- name: GetWorkspacePrincipals :many
SELECT DISTINCT
  username
FROM
  principals
WHERE
  workspace_id = @workspace_id
ORDER BY
  username ASC;
