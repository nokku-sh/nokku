-- name: CreatePrincipal :one
INSERT INTO
  principals (workspace_id, target_id, username)
SELECT
  @workspace_id,
  @target_id,
  @username
ON CONFLICT (target_id, username) DO UPDATE
SET
  username = EXCLUDED.username
RETURNING
  *;

-- name: ListPrincipals :many
WITH
  filtered AS (
    SELECT
      p.id,
      p.username
    FROM
      principals p
    WHERE
      p.target_id = @target_id
      AND (
        sqlc.narg('query')::TEXT IS NULL
        OR p.username ILIKE '%' || sqlc.narg('query') || '%'
      )
  ),
  paginated_principals AS (
    SELECT
      id
    FROM
      filtered
    ORDER BY
      username ASC
    LIMIT
      sqlc.narg('limit')
    OFFSET
      sqlc.narg('offset')
  )
SELECT
  sqlc.embed(p),
  COALESCE(
    array_agg(DISTINCT g.subject_id) FILTER (WHERE g.subject_kind = 'user'),
    '{}'
  )::UUID[] AS "userIds",
  COALESCE(
    array_agg(DISTINCT g.subject_id) FILTER (WHERE g.subject_kind = 'team'),
    '{}'
  )::UUID[] AS "teamIds",
  COALESCE(
    array_agg(DISTINCT g.subject_id) FILTER (WHERE g.subject_kind = 'service_account'),
    '{}'
  )::UUID[] AS "serviceAccountIds",
  (SELECT
    COUNT(*)::INTEGER
  FROM
    filtered) AS total_count
FROM
  principals p
  JOIN paginated_principals pp ON pp.id = p.id
  LEFT JOIN principal_grants g ON g.principal_id = p.id
GROUP BY
  p.id
ORDER BY
  p.username ASC;

-- name: SetPrincipals :exec
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

-- name: InsertTargetPrincipals :exec
-- Creates the principal anchor for each reported account so it becomes
-- assignable. Never deletes: a host's reported list is a hint, not authority.
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
  unnest(@usernames::TEXT[]) AS d (username)
ON CONFLICT (target_id, username) DO NOTHING;

-- name: GetPrincipalWorkspace :one
SELECT
  t.workspace_id
FROM
  principals p
  JOIN targets t ON t.id = p.target_id
WHERE
  p.id = @principal_id;

-- Grant primitives used by AddSubjectsToPrincipal / RemoveSubjectsFromPrincipal.
-- One row per (principal, subject kind, subject id) in principal_grants.
-- name: AddPrincipalGrant :exec
INSERT INTO
  principal_grants (principal_id, workspace_id, subject_kind, subject_id)
VALUES
  (@principal_id, @workspace_id, @subject_kind, @subject_id)
ON CONFLICT (principal_id, subject_kind, subject_id) DO NOTHING;

-- name: RemovePrincipalGrant :exec
DELETE FROM principal_grants
WHERE
  principal_id = @principal_id
  AND subject_kind = @subject_kind
  AND subject_id = @subject_id;

-- name: RevokeSubjectAccessInWorkspace :exec
DELETE FROM principal_grants
WHERE
  workspace_id = @workspace_id
  AND subject_kind = @subject_kind
  AND subject_id = @subject_id;

-- name: DeleteSubjectGrants :exec
-- Removes every grant for a subject that no longer exists, so no dangling
-- subject id outlives the user, team, or service account it pointed at.
-- Subject ids are unique across kinds and never reused.
DELETE FROM principal_grants
WHERE
  subject_kind = @subject_kind
  AND subject_id = @subject_id;

-- name: ListPrincipalsForDaemon :many
SELECT
  p.username,
  array_agg(DISTINCT ids)::TEXT[] AS ids
FROM
  principals p
  CROSS JOIN LATERAL (
    SELECT
      g.subject_id AS ids
    FROM
      principal_grants g
    WHERE
      g.principal_id = p.id
      AND g.subject_kind IN ('user', 'service_account')
    UNION
    SELECT
      tm.user_id
    FROM
      principal_grants g
      JOIN team_members tm ON tm.team_id = g.subject_id
    WHERE
      g.principal_id = p.id
      AND g.subject_kind = 'team'
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
  sqlc.embed(p),
  COALESCE(
    array_agg(DISTINCT g.subject_id) FILTER (WHERE g.subject_kind = 'user'),
    '{}'
  )::UUID[] AS user_ids,
  COALESCE(
    array_agg(DISTINCT g.subject_id) FILTER (WHERE g.subject_kind = 'team'),
    '{}'
  )::UUID[] AS team_ids,
  COALESCE(
    array_agg(DISTINCT g.subject_id) FILTER (WHERE g.subject_kind = 'service_account'),
    '{}'
  )::UUID[] AS service_account_ids
FROM
  principals p
  LEFT JOIN principal_grants g ON g.principal_id = p.id
WHERE
  p.target_id = ANY (@target_ids::UUID[])
GROUP BY
  p.id
ORDER BY
  p.username;

-- name: ListSubjectUsernamesForTargets :many
-- The local accounts a subject may log in as, per target: the grant predicate
-- resolved for one subject, without the rest of the target's assignment graph.
-- A team grant counts for its members, and a subject may be a user, a team, or
-- a service account (all identified by UUID, which is unique across them).
SELECT DISTINCT
  p.target_id,
  p.username
FROM
  principals p
WHERE
  p.target_id = ANY (@target_ids::UUID[])
  AND EXISTS (
    SELECT
      1
    FROM
      principal_grants g
    WHERE
      g.principal_id = p.id
      AND (
        g.subject_id = @subject_id
        OR (
          g.subject_kind = 'team'
          AND g.subject_id IN (
            SELECT
              tm.team_id
            FROM
              team_members tm
            WHERE
              tm.user_id = @subject_id
          )
        )
      )
  )
ORDER BY
  p.target_id,
  p.username;

-- name: ListPrincipalsForTarget :many
-- The same per-account subject list the daemon receives, for a daemonless
-- target whose sshd reads it from AuthorizedPrincipalsFile. Teams are
-- expanded to their members here, so the host needs no team knowledge.
SELECT
  p.username,
  array_agg(DISTINCT ids)::TEXT[] AS ids
FROM
  principals p
  CROSS JOIN LATERAL (
    SELECT
      g.subject_id AS ids
    FROM
      principal_grants g
    WHERE
      g.principal_id = p.id
      AND g.subject_kind IN ('user', 'service_account')
    UNION
    SELECT
      tm.user_id
    FROM
      principal_grants g
      JOIN team_members tm ON tm.team_id = g.subject_id
    WHERE
      g.principal_id = p.id
      AND g.subject_kind = 'team'
  ) AS combined (ids)
WHERE
  p.target_id = @target_id
GROUP BY
  p.username
ORDER BY
  p.username;

-- name: DeletePrincipal :exec
DELETE FROM principals
WHERE
  id = @id;
