-- name: ListRequestableAccounts :many
-- The targets members may ask for, the ones carrying one of the workspace's requestable tags.
SELECT
  t.id,
  t.name,
  COALESCE(
    array_agg(p.username ORDER BY p.username) FILTER (WHERE p.id IS NOT NULL),
    '{}'
  )::TEXT[] AS usernames
FROM
  targets t
  LEFT JOIN target_accounts p ON p.target_id = t.id
WHERE
  t.tags && (
    SELECT
      requestable_tags
    FROM
      workspaces
    WHERE
      id = current_workspace_id ()
  )
GROUP BY
  t.id
ORDER BY
  t.name;

-- name: GetRequestableAccount :one
-- The target by id or name, so nk can pass what a person types.
SELECT
  p.id
FROM
  target_accounts p
  JOIN targets t ON t.id = p.target_id
WHERE
  t.tags && (
    SELECT
      requestable_tags
    FROM
      workspaces
    WHERE
      id = current_workspace_id ()
  )
  AND (
    t.id::TEXT = @target::TEXT
    OR t.name = @target::TEXT
  )
  AND p.username = @username;

-- name: SetRequestableTags :exec
UPDATE workspaces
SET
  requestable_tags = COALESCE(@tags::TEXT[], '{}')
WHERE
  id = current_workspace_id ();

-- name: CountRecentAccessRequests :one
SELECT
  COUNT(*)::INTEGER
FROM
  access_requests
WHERE
  requester_id = @requester_id
  AND created_at > NOW() - INTERVAL '1 day';

-- name: CreateAccessRequest :one
INSERT INTO
  access_requests (requester_id, account_id, duration, reason)
VALUES
  (@requester_id, @account_id, @duration, @reason)
RETURNING
  id;

-- name: GetAccessRequest :one
SELECT
  *
FROM
  access_request_details
WHERE
  id = @id;

-- name: ListAccessRequests :many
SELECT
  sqlc.embed(r),
  COUNT(*) OVER ()::INTEGER AS total_count
FROM
  access_request_details r
WHERE
  (
    sqlc.narg('status')::TEXT IS NULL
    OR r.status = sqlc.narg('status')::TEXT
  )
  AND (
    sqlc.narg('requester_id')::UUID IS NULL
    OR r.requester_id = sqlc.narg('requester_id')::UUID
  )
ORDER BY
  r.created_at DESC
LIMIT
  sqlc.narg('limit')
OFFSET
  sqlc.narg('offset');

-- name: DecideAccessRequest :one
-- Only a pending request is decided, and never by the one who asked.
UPDATE access_requests
SET
  status = @status,
  decided_by = @decided_by::UUID,
  decided_at = NOW()
WHERE
  id = @id
  AND status = 'pending'
  AND requester_id <> @decided_by::UUID
RETURNING
  *;

-- name: CancelAccessRequest :execrows
UPDATE access_requests
SET
  status = 'cancelled'
WHERE
  id = @id
  AND requester_id = @requester_id
  AND status = 'pending';

-- name: ExpireAccessRequests :many
UPDATE access_requests
SET
  status = 'expired'
WHERE
  status = 'pending'
  AND created_at < NOW() - INTERVAL '1 day'
RETURNING
  id,
  workspace_id;

-- name: ListApprovers :many
SELECT
  id,
  name,
  email
FROM
  users
WHERE
  role >= 4
  AND active
  AND id <> @requester_id;
