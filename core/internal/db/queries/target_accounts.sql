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

-- name: GetTargetAccountLabel :one
-- What an audit event shows for a login account. An account of another workspace does not exist here.
SELECT
  t.name AS target_name,
  p.username
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

-- name: GrantWhere :many
-- The servers a batch grant names, by id or by tag, each with the account asked for if it has one.
SELECT
  t.id,
  t.name,
  a.id AS account_id
FROM
  targets t
  LEFT JOIN target_accounts a ON a.target_id = t.id
  AND a.username = @username
WHERE
  t.id = ANY (@target_ids::UUID[])
  OR t.tags && @tags::TEXT[]
ORDER BY
  t.name;

-- name: GrantWhereAccounts :many
-- The accounts those servers have, the most common first.
SELECT
  a.username,
  COUNT(*)::INT AS servers
FROM
  targets t
  JOIN target_accounts a ON a.target_id = t.id
WHERE
  t.id = ANY (@target_ids::UUID[])
  OR t.tags && @tags::TEXT[]
GROUP BY
  a.username
ORDER BY
  servers DESC,
  a.username;

-- name: ListGrantEnds :many
-- What one subject holds on these accounts already. A grant that ran out counts as none.
SELECT
  account_id,
  expires_at
FROM
  live_grants
WHERE
  account_id = ANY (@account_ids::UUID[])
  AND subject_id = @subject_id;

-- name: PutGrants :exec
-- PutGrant for many accounts in one statement.
INSERT INTO
  grants (
    account_id,
    user_id,
    team_id,
    service_account_id,
    expires_at
  )
SELECT
  account_id,
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
FROM
  unnest(@account_ids::UUID[]) AS account_id
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
-- One workspace at a time, the trigger notifies once per transaction and workspace.
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
  t.name AS target_name,
  COALESCE(NULLIF(u.name, ''), u.email, m.name, s.name, '')::TEXT AS subject_name
FROM
  gone
  JOIN target_accounts p ON p.id = gone.account_id
  JOIN targets t ON t.id = p.target_id
  LEFT JOIN users u ON u.id = gone.subject_id
  LEFT JOIN teams m ON m.id = gone.subject_id
  LEFT JOIN service_accounts s ON s.id = gone.subject_id;

-- name: RemoveGrant :exec
DELETE FROM grants
WHERE
  account_id = @account_id
  AND subject_kind = @subject_kind::TEXT
  AND subject_id = @subject_id::UUID;

-- name: RevokeWhere :many
-- One subject's own grants on the servers a batch revoke names, by id or by tag.
SELECT
  g.account_id,
  a.username,
  t.id AS target_id,
  t.name,
  (cardinality(t.tags) > 1)::BOOLEAN AS other_tags
FROM
  grants g
  JOIN target_accounts a ON a.id = g.account_id
  JOIN targets t ON t.id = a.target_id
WHERE
  g.subject_kind = @subject_kind::TEXT
  AND g.subject_id = @subject_id::UUID
  AND (
    t.id = ANY (@target_ids::UUID[])
    OR t.tags && @tags::TEXT[]
  )
ORDER BY
  t.name,
  a.username;

-- name: RemoveGrants :exec
-- RemoveGrant for many accounts in one statement.
DELETE FROM grants
WHERE
  account_id = ANY (@account_ids::UUID[])
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
-- What a person or a service account holds on each target, a team's own grants for a team. The access lasts until
-- the latest grant that applies ends, or for good when one of them is. user_ok and daemon_ok say whether it lets
-- anyone in today, see effective_access. A team's rows are its grants as given, they carry no mark.
SELECT
  a.target_id,
  a.username,
  bool_or(a.expires_at IS NULL)::BOOLEAN AS for_good,
  -- Only read when not for good, then no grant has a NULL. The epoch keeps the column scannable.
  COALESCE(max(a.expires_at), 'epoch')::TIMESTAMPTZ AS expires_at,
  bool_and(a.user_ok)::BOOLEAN AS user_ok,
  bool_and(a.daemon_ok)::BOOLEAN AS daemon_ok
FROM
  (
    SELECT
      e.target_id,
      e.username,
      e.expires_at,
      e.user_ok,
      e.daemon_ok
    FROM
      effective_access e
    WHERE
      e.subject_id = @subject_id
    UNION ALL
    SELECT
      p.target_id,
      p.username,
      g.expires_at,
      TRUE,
      TRUE
    FROM
      live_grants g
      JOIN target_accounts p ON p.id = g.account_id
    WHERE
      g.team_id = @subject_id
  ) a
WHERE
  a.target_id = ANY (@target_ids::UUID[])
GROUP BY
  a.target_id,
  a.username
ORDER BY
  a.target_id,
  a.username;

-- name: ListAccountSubjectsForTarget :many
-- Who a server lets in as which account, as the subjects its certificates name.
SELECT
  e.username,
  -- Sorted, the answer to a daemon is hashed.
  array_agg(
    DISTINCT e.subject_id
    ORDER BY
      e.subject_id
  )::TEXT[] AS ids
FROM
  effective_access e
WHERE
  e.target_id = @target_id
  AND e.user_ok
  AND e.daemon_ok
GROUP BY
  e.username
ORDER BY
  e.username;

-- name: ListAccountSubjects :many
-- ListAccountSubjectsForTarget for every server of the workspace at once, in the same order.
SELECT
  e.target_id,
  e.username,
  array_agg(
    DISTINCT e.subject_id
    ORDER BY
      e.subject_id
  )::TEXT[] AS ids
FROM
  effective_access e
WHERE
  e.user_ok
  AND e.daemon_ok
GROUP BY
  e.target_id,
  e.username
ORDER BY
  e.target_id,
  e.username;

-- name: DeleteTargetAccount :exec
DELETE FROM target_accounts
WHERE
  id = @id;
