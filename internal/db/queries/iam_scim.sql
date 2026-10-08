-- name: ListSCIMUsers :many
SELECT
  sqlc.embed(u),
  COALESCE(c.subject, '')::TEXT AS external_id
FROM
  users u
  LEFT JOIN credentials c ON c.workspace_id = u.workspace_id
  AND c.user_id = u.id
  AND c.type = 'scim'
WHERE
  (
    sqlc.narg('user_id')::UUID IS NULL
    OR u.id = sqlc.narg('user_id')
  )
  AND (
    sqlc.narg('email')::TEXT IS NULL
    OR u.email = sqlc.narg('email')
  )
ORDER BY
  u.created_at ASC,
  u.id ASC;

-- name: DeleteUserSCIMCredentials :exec
DELETE FROM credentials
WHERE
  user_id = @user_id
  AND type = 'scim';

-- name: DeleteStaleUserSCIMCredentials :exec
-- Run before UpsertCredential so one account never carries two links.
DELETE FROM credentials
WHERE
  user_id = @user_id
  AND type = 'scim'
  AND subject <> @subject;
