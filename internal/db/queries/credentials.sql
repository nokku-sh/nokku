-- Credentials (kagi Credential) ----------------------------------------------
-- name: PutCredential :exec
INSERT INTO
  credentials (
    tenant_id,
    id,
    user_id,
    type,
    provider,
    subject,
    data,
    label,
    created_at,
    updated_at
  )
VALUES
  (
    @tenant_id,
    @id,
    @user_id,
    @type,
    @provider,
    @subject,
    sqlc.narg('data'),
    @label,
    @created_at,
    @updated_at
  )
ON CONFLICT (tenant_id, id) DO UPDATE
SET
  user_id = EXCLUDED.user_id,
  type = EXCLUDED.type,
  provider = EXCLUDED.provider,
  subject = EXCLUDED.subject,
  data = EXCLUDED.data,
  label = EXCLUDED.label,
  updated_at = EXCLUDED.updated_at;

-- name: ListCredentials :many
SELECT
  *
FROM
  credentials
WHERE
  user_id = @user_id
  AND type = @type;

-- name: GetCredential :one
SELECT
  *
FROM
  credentials
WHERE
  id = @id
  AND user_id = @user_id;

-- name: FindCredentialBySubject :one
SELECT
  *
FROM
  credentials
WHERE
  type = @type
  AND provider = @provider
  AND subject = @subject;

-- name: ConsumeCredentialBySubject :one
DELETE FROM credentials
WHERE
  type = @type
  AND provider = @provider
  AND subject = @subject
  AND user_id = @user_id
RETURNING
  *;

-- name: DeleteCredential :exec
DELETE FROM credentials
WHERE
  id = @id
  AND user_id = @user_id;

-- name: DeleteCredentialsByProvider :exec
DELETE FROM credentials
WHERE
  provider = @provider
  AND type = @type;
