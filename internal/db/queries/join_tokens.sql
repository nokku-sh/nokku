-- name: CreateJoinToken :one
INSERT INTO
  join_tokens (
    id,
    kind,
    label,
    token_hash,
    expires_at,
    max_uses,
    auto_approve,
    ca_id,
    role
  )
VALUES
  (
    @id,
    @kind,
    @label,
    @token_hash,
    sqlc.narg('expires_at'),
    sqlc.narg('max_uses'),
    @auto_approve,
    sqlc.narg('ca_id'),
    sqlc.narg('role')
  )
RETURNING
  *;

-- name: ListJoinTokens :many
SELECT
  *
FROM
  join_tokens
WHERE
  (
    kind = @kind
    OR @kind = 0
  )
ORDER BY
  created_at DESC;

-- name: DeleteJoinToken :exec
DELETE FROM join_tokens
WHERE
  id = @id;

-- name: GetLiveJoinToken :one
-- Ignores the use limit, so a used-up token still identifies a daemon it
-- already enrolled. RedeemJoinToken enforces it.
SELECT
  *
FROM
  join_tokens
WHERE
  id = @id
  AND kind = @kind
  AND token_hash = @token_hash
  AND (
    expires_at IS NULL
    OR expires_at > NOW()
  );

-- name: RedeemJoinToken :one
-- One statement, so two redemptions can never both take the last use.
UPDATE join_tokens
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

-- name: RedeemJoinTokenByID :one
-- For a signup whose invite link was checked earlier. The mailed link or
-- the passkey ceremony is the proof by then.
UPDATE join_tokens
SET
  uses = uses + 1,
  last_used_at = NOW()
WHERE
  id = @id
  AND kind = @kind
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
