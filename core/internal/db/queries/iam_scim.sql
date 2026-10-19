-- name: ListSCIMUsers :many
SELECT
  *
FROM
  users u
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

-- name: SetUserSCIMExternalID :exec
-- NULL takes the link away. An id another account holds trips the unique constraint.
UPDATE users
SET
  scim_external_id = sqlc.narg('external_id'),
  updated_at = NOW()
WHERE
  id = @id;

-- name: SetTeamSCIMExternalID :one
-- Like SetUserSCIMExternalID, for a SCIM group.
UPDATE teams
SET
  scim_external_id = sqlc.narg('external_id'),
  updated_at = NOW()
WHERE
  id = @id
RETURNING
  *;

-- name: GetTeamByName :one
-- A SCIM create takes over a team of that name that no group is linked to yet.
SELECT
  *
FROM
  teams
WHERE
  name = @name;
