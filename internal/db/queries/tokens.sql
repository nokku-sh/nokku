-- name: CreateWorkspaceToken :one
INSERT INTO
  workspace_tokens (
    id,
    workspace_id,
    kind,
    label,
    token_hash,
    expires_at,
    max_uses,
    auto_approve,
    ca_id,
    role_name
  )
VALUES
  (
    @id,
    @workspace_id,
    @kind,
    @label,
    @token_hash,
    sqlc.narg('expires_at'),
    sqlc.narg('max_uses'),
    @auto_approve,
    sqlc.narg('ca_id'),
    sqlc.narg('role_name')
  )
RETURNING
  *;

-- name: ListWorkspaceTokens :many
SELECT
  *
FROM
  workspace_tokens
WHERE
  workspace_id = @workspace_id
  AND (
    kind = @kind
    OR @kind = 0
  )
ORDER BY
  created_at DESC;

-- name: DeleteWorkspaceToken :exec
DELETE FROM workspace_tokens
WHERE
  id = @id;

-- name: GetLiveToken :one
-- A known, unexpired token. The use limit is enforced by RedeemToken, so a
-- token that ran out still identifies a daemon it already enrolled.
SELECT
  *
FROM
  workspace_tokens
WHERE
  id = @id
  AND kind = @kind
  AND token_hash = @token_hash
  AND (
    expires_at IS NULL
    OR expires_at > NOW()
  );

-- name: RedeemToken :one
-- Spends one use. The checks and the increment are one statement, so two
-- redemptions can never both take the last use.
UPDATE workspace_tokens
SET
  uses = uses + 1,
  last_used_at = NOW()
WHERE
  id = @id
  AND kind = @kind
  AND token_hash = @token_hash
  AND (
    expires_at IS NULL
    OR expires_at > NOW()
  )
  AND (
    max_uses IS NULL
    OR uses < max_uses
  )
RETURNING
  *;
