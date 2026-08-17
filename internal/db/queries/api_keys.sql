-- API keys (kagi APIKeyRecord) ------------------------------------------------
-- name: PutKey :exec
INSERT INTO
  api_keys (
    key_id,
    tenant_id,
    subject_id,
    kind,
    secret_hash,
    scopes,
    name,
    expires_at,
    created_at
  )
VALUES
  (
    @key_id,
    @tenant_id,
    @subject_id,
    @kind,
    @secret_hash,
    @scopes,
    @name,
    sqlc.narg('expires_at'),
    @created_at
  )
ON CONFLICT (key_id) DO UPDATE
SET
  tenant_id = EXCLUDED.tenant_id,
  subject_id = EXCLUDED.subject_id,
  kind = EXCLUDED.kind,
  secret_hash = EXCLUDED.secret_hash,
  scopes = EXCLUDED.scopes,
  name = EXCLUDED.name,
  expires_at = EXCLUDED.expires_at;

-- name: GetKey :one
SELECT
  *
FROM
  api_keys
WHERE
  key_id = @key_id;

-- name: DeleteKey :exec
DELETE FROM api_keys
WHERE
  key_id = @key_id;

-- name: ListKeys :many
SELECT
  *
FROM
  api_keys
WHERE
  tenant_id = @tenant_id
  AND subject_id = @subject_id;

-- name: ListTenantKeys :many
SELECT
  *
FROM
  api_keys
WHERE
  tenant_id = @tenant_id;
