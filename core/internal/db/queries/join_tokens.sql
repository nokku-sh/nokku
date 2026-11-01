-- name: CreateJoinToken :one
INSERT INTO
  join_tokens (
    label,
    token_hash,
    expires_at,
    max_uses,
    auto_approve,
    tags,
    retire_after
  )
VALUES
  (
    @label,
    @token_hash,
    sqlc.narg('expires_at'),
    sqlc.narg('max_uses'),
    @auto_approve,
    COALESCE(sqlc.narg('tags')::TEXT[], '{}'),
    sqlc.narg('retire_after')
  )
RETURNING
  *;

-- name: AddJoinTokenGrant :exec
-- One row per subject, the kind picks the column like AddGrant.
INSERT INTO
  join_token_grants (token_id, username, user_id, team_id, service_account_id)
VALUES
  (
    @token_id,
    @username,
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

-- name: ListJoinTokenGrants :many
SELECT
  token_id,
  username,
  subject_kind,
  subject_id
FROM
  join_token_grants
ORDER BY
  token_id,
  username,
  subject_kind,
  subject_id;

-- name: ListJoinTokens :many
SELECT
  *
FROM
  join_tokens
ORDER BY
  created_at DESC;

-- name: DeleteJoinToken :exec
DELETE FROM join_tokens
WHERE
  id = @id;

-- name: GetLiveJoinToken :one
-- Ignores the use limit, so a used-up token still identifies a daemon it enrolled. RedeemJoinToken enforces it.
SELECT
  *
FROM
  join_tokens
WHERE
  token_hash = @token_hash
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
  token_hash = @token_hash
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
