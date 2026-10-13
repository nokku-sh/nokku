-- name: UpsertCredential :one
INSERT INTO
  credentials (id, user_id, type, provider, subject, data, label)
VALUES
  (@id, @user_id, @type, @provider, @subject, @data, @label)
ON CONFLICT (id) DO UPDATE
SET
  type = EXCLUDED.type,
  provider = EXCLUDED.provider,
  subject = EXCLUDED.subject,
  data = EXCLUDED.data,
  label = EXCLUDED.label,
  updated_at = NOW()
-- A credential never moves accounts, a clash returns no rows.
WHERE
  credentials.user_id = EXCLUDED.user_id
RETURNING
  *;

-- name: ListCredentialsByType :many
SELECT
  *
FROM
  credentials
WHERE
  user_id = @user_id
  AND type = @type
ORDER BY
  created_at ASC;

-- name: ListUserCredentials :many
SELECT
  *
FROM
  credentials
WHERE
  user_id = @user_id
ORDER BY
  type ASC,
  created_at ASC;

-- name: FindCredentialBySubject :one
SELECT
  *
FROM
  credentials
WHERE
  type = @type
  AND provider = @provider
  AND subject = @subject;

-- name: RenameCredential :exec
UPDATE credentials
SET
  label = @label,
  updated_at = NOW()
WHERE
  user_id = @user_id
  AND id = @id;

-- name: DeleteCredential :exec
DELETE FROM credentials
WHERE
  user_id = @user_id
  AND id = @id;

-- name: DeleteUserCredentials :exec
DELETE FROM credentials
WHERE
  user_id = @user_id;

-- name: DeleteCredentialsByProvider :execrows
DELETE FROM credentials
WHERE
  type = @type
  AND provider = @provider;

-- name: TouchCredential :exec
UPDATE credentials
SET
  last_used_at = NOW()
WHERE
  id = @id;
