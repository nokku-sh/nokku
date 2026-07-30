-- name: CreatePrincipal :one
INSERT INTO
  principals (workspace_id, target_id, username)
SELECT
  @workspace_id,
  @target_id,
  @username
RETURNING
  *;

-- name: GetPrincipals :many
SELECT
  p.*,
  COALESCE(
    array_agg(DISTINCT pu.user_id) FILTER (
      WHERE
        pu.user_id IS NOT NULL
    ),
    '{}'
  )::UUID[] AS user_ids,
  COALESCE(
    array_agg(DISTINCT pt.team_id) FILTER (
      WHERE
        pt.team_id IS NOT NULL
    ),
    '{}'
  )::UUID[] AS team_ids,
  COALESCE(
    array_agg(DISTINCT psa.service_account_id) FILTER (
      WHERE
        psa.service_account_id IS NOT NULL
    ),
    '{}'
  )::UUID[] AS service_account_ids
FROM
  principals p
  LEFT JOIN principal_users pu ON pu.principal_id = p.id
  LEFT JOIN principal_teams pt ON pt.principal_id = p.id
  LEFT JOIN principal_service_accounts psa ON psa.principal_id = p.id
WHERE
  p.id = ANY (@principal_ids::UUID[])
GROUP BY
  p.id;

-- name: CountTargetPrincipals :one
SELECT
  COUNT(*)::INTEGER
FROM
  principals
WHERE
  target_id = @target_id;

-- name: GetTargetUsernames :many
SELECT
  username
FROM
  principals
WHERE
  target_id = @target_id;

-- name: SyncPrincipals :exec
WITH
  desired AS (
    SELECT
      unnest(@usernames::TEXT[]) AS username
  ),
  deleted AS (
    DELETE FROM principals
    WHERE
      target_id = @target_id
      AND username NOT IN (
        SELECT
          username
        FROM
          desired
      )
  )
INSERT INTO
  principals (workspace_id, target_id, username)
SELECT
  (
    SELECT
      workspace_id
    FROM
      targets
    WHERE
      id = @target_id
  ),
  @target_id,
  d.username
FROM
  desired d
ON CONFLICT (target_id, username) DO NOTHING;

-- name: GetPrincipalWorkspace :one
SELECT
  t.workspace_id
FROM
  principals p
  JOIN targets t ON t.id = p.target_id
WHERE
  p.id = @principal_id;

-- name: AddUsersToPrincipal :exec
WITH
  deletions AS (
    DELETE FROM principal_users
    WHERE
      principal_id = @principal_id::uuid
      AND user_id != ALL (@user_ids::UUID[])
  )
INSERT INTO
  principal_users (principal_id, workspace_id, user_id)
SELECT
  @principal_id::uuid,
  @workspace_id::uuid,
  UNNEST(@user_ids::UUID[])
ON CONFLICT DO NOTHING;

-- name: RemoveUsersFromPrincipal :exec
DELETE FROM principal_users
WHERE
  principal_id = @principal_id::uuid
  AND user_id = ANY (@user_ids::UUID[]);

-- name: AddTeamsToPrincipal :exec
WITH
  deletions AS (
    DELETE FROM principal_teams
    WHERE
      principal_id = @principal_id::uuid
      AND team_id != ALL (@team_ids::UUID[])
  )
INSERT INTO
  principal_teams (principal_id, workspace_id, team_id)
SELECT
  @principal_id::uuid,
  @workspace_id::uuid,
  UNNEST(@team_ids::UUID[])
ON CONFLICT DO NOTHING;

-- name: RemoveTeamsFromPrincipal :exec
DELETE FROM principal_teams
WHERE
  principal_id = @principal_id::uuid
  AND team_id = ANY (@team_ids::UUID[]);

-- name: AddServiceAccountsToPrincipal :exec
WITH
  deletions AS (
    DELETE FROM principal_service_accounts
    WHERE
      principal_id = @principal_id::uuid
      AND service_account_id != ALL (@service_account_ids::UUID[])
  )
INSERT INTO
  principal_service_accounts (principal_id, workspace_id, service_account_id)
SELECT
  @principal_id::uuid,
  @workspace_id::uuid,
  UNNEST(@service_account_ids::UUID[])
ON CONFLICT DO NOTHING;

-- name: RemoveServiceAccountsFromPrincipal :exec
DELETE FROM principal_service_accounts
WHERE
  principal_id = @principal_id::uuid
  AND service_account_id = ANY (@service_account_ids::UUID[]);

-- name: RevokeUserAccessInWorkspace :exec
DELETE FROM principal_users
WHERE
  workspace_id = @workspace_id
  AND user_id = @user_id;

-- name: RevokeTeamAccessInWorkspace :exec
DELETE FROM principal_teams
WHERE
  workspace_id = @workspace_id
  AND team_id = @team_id;

-- name: RevokeServiceAccountAccessInWorkspace :exec
DELETE FROM principal_service_accounts
WHERE
  workspace_id = @workspace_id
  AND service_account_id = @service_account_id;

-- name: ListPrincipalsForDaemon :many
SELECT
  p.username,
  array_agg(DISTINCT ids)::TEXT[] AS ids
FROM
  principals p
  CROSS JOIN LATERAL (
    SELECT
      pu.user_id
    FROM
      principal_users pu
    WHERE
      pu.principal_id = p.id
    UNION
    SELECT
      tm.user_id
    FROM
      principal_teams pt
      JOIN team_members tm ON tm.team_id = pt.team_id
    WHERE
      pt.principal_id = p.id
    UNION
    SELECT
      psa.service_account_id
    FROM
      principal_service_accounts psa
    WHERE
      psa.principal_id = p.id
  ) AS combined (ids)
WHERE
  p.target_id = (
    SELECT
      t.id
    FROM
      targets t
    WHERE
      t.daemon_id = @daemon_id
  )
GROUP BY
  p.username
ORDER BY
  p.username;

-- name: GetPrincipalsByTargetIDs :many
SELECT
  p.*,
  COALESCE(
    array_agg(DISTINCT pu.user_id) FILTER (WHERE pu.user_id IS NOT NULL),
    '{}'
  )::UUID[] AS user_ids,
  COALESCE(
    array_agg(DISTINCT pt.team_id) FILTER (WHERE pt.team_id IS NOT NULL),
    '{}'
  )::UUID[] AS team_ids,
  COALESCE(
    array_agg(DISTINCT psa.service_account_id) FILTER (WHERE psa.service_account_id IS NOT NULL),
    '{}'
  )::UUID[] AS service_account_ids
FROM
  principals p
  LEFT JOIN principal_users pu ON pu.principal_id = p.id
  LEFT JOIN principal_teams pt ON pt.principal_id = p.id
  LEFT JOIN principal_service_accounts psa ON psa.principal_id = p.id
WHERE
  p.target_id = ANY (@target_ids::UUID[])
GROUP BY
  p.id;

-- name: ListPrincipals :many
WITH
  paginated_principals AS (
    SELECT
      p.id
    FROM
      principals p
    WHERE
      p.target_id = @target_id
      AND (
        sqlc.narg('query')::TEXT IS NULL
        OR p.username ILIKE '%' || sqlc.narg('query') || '%'
      )
    ORDER BY
      p.username ASC
    LIMIT
      sqlc.narg('limit')
    OFFSET
      sqlc.narg('offset')
  )
SELECT
  p.*,
  COALESCE(
    array_agg(DISTINCT pu.user_id) FILTER (WHERE pu.user_id IS NOT NULL),
    '{}'
  )::UUID[] AS "userIds",
  COALESCE(
    array_agg(DISTINCT pt.team_id) FILTER (WHERE pt.team_id IS NOT NULL),
    '{}'
  )::UUID[] AS "teamIds",
  COALESCE(
    array_agg(DISTINCT psa.service_account_id) FILTER (WHERE psa.service_account_id IS NOT NULL),
    '{}'
  )::UUID[] AS "serviceAccountIds"
FROM
  principals p
  JOIN paginated_principals pp ON pp.id = p.id
  LEFT JOIN principal_users pu ON pu.principal_id = p.id
  LEFT JOIN principal_teams pt ON pt.principal_id = p.id
  LEFT JOIN principal_service_accounts psa ON psa.principal_id = p.id
GROUP BY
  p.id
ORDER BY
  p.username ASC;

