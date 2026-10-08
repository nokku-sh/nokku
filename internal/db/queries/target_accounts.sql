-- name: CreateTargetAccount :one
INSERT INTO
  target_accounts (target_id, username)
SELECT
  @target_id,
  @username
ON CONFLICT (target_id, username) DO UPDATE
SET
  username = EXCLUDED.username
RETURNING
  *;

-- name: ListTargetAccounts :many
WITH
  filtered AS (
    SELECT
      p.id,
      p.username
    FROM
      target_accounts p
    WHERE
      p.target_id = @target_id
      AND (
        sqlc.narg('query')::TEXT IS NULL
        OR p.username ILIKE '%' || sqlc.narg('query') || '%'
      )
  ),
  paginated AS (
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
  target_accounts p
  JOIN paginated pp ON pp.id = p.id
  LEFT JOIN grants g ON g.account_id = p.id
GROUP BY
  p.id
ORDER BY
  p.username ASC;

-- name: InsertTargetAccounts :exec
-- Never deletes, a host's reported list is a hint, not authority. A target
-- that already holds max_accounts takes no more, so a host cannot grow the
-- table without bound.
INSERT INTO
  target_accounts (workspace_id, target_id, username)
SELECT
  t.workspace_id,
  t.id,
  d.username
FROM
  targets t
  CROSS JOIN unnest(@usernames::TEXT[]) AS d (username)
WHERE
  t.id = @target_id
  AND (
    SELECT
      COUNT(*)
    FROM
      target_accounts p
    WHERE
      p.target_id = t.id
  ) < @max_accounts::INTEGER
ON CONFLICT (target_id, username) DO NOTHING;

-- name: GetTargetAccountWorkspace :one
SELECT
  t.workspace_id
FROM
  target_accounts p
  JOIN targets t ON t.id = p.target_id
WHERE
  p.id = @account_id;

-- name: AddGrant :exec
INSERT INTO
  grants (
    account_id,
    user_id,
    team_id,
    service_account_id
  )
VALUES
  (
    @account_id,
    CASE
      WHEN @subject_kind::TEXT = 'user' THEN @subject_id::UUID
    END,
    CASE
      WHEN @subject_kind::TEXT = 'team' THEN @subject_id::UUID
    END,
    CASE
      WHEN @subject_kind::TEXT = 'service_account' THEN @subject_id::UUID
    END
  )
ON CONFLICT DO NOTHING;

-- name: RemoveGrant :exec
DELETE FROM grants
WHERE
  account_id = @account_id
  AND subject_kind = @subject_kind::TEXT
  AND subject_id = @subject_id::UUID;

-- name: RevokeSubjectAccessInWorkspace :exec
DELETE FROM grants
WHERE
  subject_kind = @subject_kind::TEXT
  AND subject_id = @subject_id::UUID;

-- name: GetTargetAccountsByTargetIDs :many
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
  target_accounts p
  LEFT JOIN grants g ON g.account_id = p.id
WHERE
  p.target_id = ANY (@target_ids::UUID[])
GROUP BY
  p.id
ORDER BY
  p.username;

-- name: ListSubjectUsernamesForTargets :many
-- A team grant counts for its members. Subject UUIDs are unique across kinds.
SELECT DISTINCT
  p.target_id,
  p.username
FROM
  target_accounts p
WHERE
  p.target_id = ANY (@target_ids::UUID[])
  AND EXISTS (
    SELECT
      1
    FROM
      grants g
    WHERE
      g.account_id = p.id
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

-- name: ListAccountSubjectsForTarget :many
-- Teams are expanded so the host needs no team knowledge. Users are joined,
-- not filtered, so an account that is inactive or not visible drops out.
SELECT
  p.username,
  array_agg(DISTINCT ids)::TEXT[] AS ids
FROM
  target_accounts p
  CROSS JOIN LATERAL (
    SELECT
      g.subject_id AS ids
    FROM
      grants g
    WHERE
      g.account_id = p.id
      AND g.subject_kind = 'service_account'
    UNION
    SELECT
      u.id
    FROM
      grants g
      JOIN users u ON u.id = g.subject_id
      AND u.active
    WHERE
      g.account_id = p.id
      AND g.subject_kind = 'user'
    UNION
    SELECT
      u.id
    FROM
      grants g
      JOIN team_members tm ON tm.team_id = g.subject_id
      JOIN users u ON u.id = tm.user_id
      AND u.active
    WHERE
      g.account_id = p.id
      AND g.subject_kind = 'team'
  ) AS combined (ids)
WHERE
  p.target_id = @target_id
GROUP BY
  p.username
ORDER BY
  p.username;

-- name: DeleteTargetAccount :exec
DELETE FROM target_accounts
WHERE
  id = @id;
