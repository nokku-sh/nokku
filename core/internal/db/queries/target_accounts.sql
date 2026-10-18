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
  -- Two arrays in the same order, the subjects whose grant ends and when.
  COALESCE(
    array_agg(g.subject_id ORDER BY g.subject_id) FILTER (WHERE g.expires_at IS NOT NULL),
    '{}'
  )::UUID[] AS "expiringIds",
  COALESCE(
    array_agg(g.expires_at ORDER BY g.subject_id) FILTER (WHERE g.expires_at IS NOT NULL),
    '{}'
  )::TIMESTAMPTZ[] AS "expiresAt",
  (SELECT
    COUNT(*)::INTEGER
  FROM
    filtered) AS total_count
FROM
  target_accounts p
  JOIN paginated pp ON pp.id = p.id
  LEFT JOIN live_grants g ON g.account_id = p.id
GROUP BY
  p.id
ORDER BY
  p.username ASC;

-- name: InsertTargetAccounts :exec
-- Never deletes, a host's list is a hint. A target that holds max_accounts takes no more. The first report
-- of an account stamps it seen, later ones leave the row alone.
INSERT INTO
  target_accounts (workspace_id, target_id, username, seen_at)
SELECT
  t.workspace_id,
  t.id,
  d.username,
  NOW()
FROM
  targets t
  -- A name reported twice would hit the same row twice, which ON CONFLICT refuses.
  CROSS JOIN (
    SELECT DISTINCT
      username
    FROM
      unnest(@usernames::TEXT[]) AS u (username)
  ) AS d
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
ON CONFLICT (target_id, username) DO UPDATE
SET
  seen_at = NOW()
WHERE
  target_accounts.seen_at IS NULL;

-- name: SeedTargetAccountsFromToken :exec
-- Copies an enroll token's grants onto a fresh target. Runs once, when the daemon is created.
WITH
  accounts AS (
    INSERT INTO
      target_accounts (workspace_id, target_id, username)
    SELECT DISTINCT
      g.workspace_id,
      @target_id::UUID,
      g.username
    FROM
      join_token_grants g
    WHERE
      g.token_id = @token_id
    ON CONFLICT (target_id, username) DO UPDATE
    SET
      username = EXCLUDED.username
    RETURNING
      id,
      username
  )
INSERT INTO
  grants (account_id, user_id, team_id, service_account_id)
SELECT
  a.id,
  g.user_id,
  g.team_id,
  g.service_account_id
FROM
  join_token_grants g
  JOIN accounts a ON a.username = g.username
WHERE
  g.token_id = @token_id
ON CONFLICT DO NOTHING;

-- name: GetTargetAccountWorkspace :one
SELECT
  t.workspace_id
FROM
  target_accounts p
  JOIN targets t ON t.id = p.target_id
WHERE
  p.id = @account_id;

-- name: PutGrant :exec
-- An admin's grant, the expiry is set exactly as asked. It can extend, shorten or end an expiry.
INSERT INTO
  grants (
    account_id,
    user_id,
    team_id,
    service_account_id,
    expires_at
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
    END,
    sqlc.narg('expires_at')::TIMESTAMPTZ
  )
ON CONFLICT (account_id, subject_id) DO UPDATE
SET
  expires_at = EXCLUDED.expires_at;

-- name: ExtendGrant :exec
-- An approved request never shortens access the user already has. A grant for good stays one.
INSERT INTO
  grants (account_id, user_id, expires_at)
VALUES
  (@account_id, @user_id::UUID, @expires_at::TIMESTAMPTZ)
ON CONFLICT (account_id, subject_id) DO UPDATE
SET
  expires_at = CASE
    WHEN grants.expires_at IS NULL THEN NULL
    ELSE GREATEST(grants.expires_at, EXCLUDED.expires_at)
  END;

-- name: ListWorkspacesWithExpiredGrants :many
SELECT DISTINCT
  workspace_id
FROM
  grants
WHERE
  expires_at <= NOW();

-- name: DeleteExpiredGrants :many
-- One workspace at a time, the state version is bumped once per transaction and workspace.
WITH
  gone AS (
    DELETE FROM grants g
    WHERE
      g.workspace_id = @workspace_id
      AND g.expires_at <= NOW()
    RETURNING
      g.account_id,
      g.subject_kind,
      g.subject_id,
      g.expires_at
  )
SELECT
  gone.account_id,
  gone.subject_kind,
  gone.subject_id,
  gone.expires_at::TIMESTAMPTZ AS expires_at,
  p.username,
  t.name AS target_name
FROM
  gone
  JOIN target_accounts p ON p.id = gone.account_id
  JOIN targets t ON t.id = p.target_id;

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
  )::UUID[] AS service_account_ids,
  COALESCE(
    array_agg(g.subject_id ORDER BY g.subject_id) FILTER (WHERE g.expires_at IS NOT NULL),
    '{}'
  )::UUID[] AS expiring_ids,
  COALESCE(
    array_agg(g.expires_at ORDER BY g.subject_id) FILTER (WHERE g.expires_at IS NOT NULL),
    '{}'
  )::TIMESTAMPTZ[] AS expires_at
FROM
  target_accounts p
  LEFT JOIN live_grants g ON g.account_id = p.id
WHERE
  p.target_id = ANY (@target_ids::UUID[])
GROUP BY
  p.id
ORDER BY
  p.username;

-- name: ListSubjectUsernamesForTargets :many
-- A team grant counts for its members. Subject UUIDs are unique across kinds. The access lasts until the latest
-- grant that applies ends, or for good when one of them is.
SELECT
  p.target_id,
  p.username,
  bool_or(g.expires_at IS NULL)::BOOLEAN AS for_good,
  -- Only read when not for good, then no grant has a NULL. The epoch keeps the column scannable.
  COALESCE(max(g.expires_at), 'epoch')::TIMESTAMPTZ AS expires_at
FROM
  target_accounts p
  JOIN live_grants g ON g.account_id = p.id
WHERE
  p.target_id = ANY (@target_ids::UUID[])
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
GROUP BY
  p.target_id,
  p.username
ORDER BY
  p.target_id,
  p.username;

-- name: ListAccountSubjectsForTarget :many
-- Teams are expanded so the host needs no team knowledge. Users are joined, so an inactive account drops out.
SELECT
  p.username,
  array_agg(DISTINCT ids)::TEXT[] AS ids
FROM
  target_accounts p
  CROSS JOIN LATERAL (
    SELECT
      g.subject_id AS ids
    FROM
      live_grants g
    WHERE
      g.account_id = p.id
      AND g.subject_kind = 'service_account'
    UNION
    SELECT
      u.id
    FROM
      live_grants g
      JOIN users u ON u.id = g.subject_id
      AND u.active
    WHERE
      g.account_id = p.id
      AND g.subject_kind = 'user'
    UNION
    SELECT
      u.id
    FROM
      live_grants g
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
