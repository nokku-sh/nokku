-- name: UpsertSSOProvider :one
INSERT INTO
  sso_providers (workspace_id, provider_id, method, name, enabled, config, secret_enc)
VALUES
  (@workspace_id, @provider_id, @method, @name, @enabled, @config, @secret_enc)
ON CONFLICT (provider_id) DO UPDATE
SET
  workspace_id = EXCLUDED.workspace_id,
  method = EXCLUDED.method,
  name = EXCLUDED.name,
  enabled = EXCLUDED.enabled,
  config = EXCLUDED.config,
  secret_enc = EXCLUDED.secret_enc,
  updated_at = NOW()
RETURNING
  *;

-- name: GetSSOProvider :one
SELECT
  *
FROM
  sso_providers
WHERE
  provider_id = @provider_id;

-- name: DeleteSSOProvider :exec
DELETE FROM sso_providers
WHERE
  provider_id = @provider_id;

-- name: DeleteTenantSSOProviders :execrows
DELETE FROM sso_providers
WHERE
  workspace_id = @workspace_id;

-- name: GetSAMLKeypair :one
SELECT
  key_enc,
  cert_pem
FROM
  saml_keypair
WHERE
  id = 1;

-- name: PutSAMLKeypair :one
INSERT INTO
  saml_keypair (id, key_enc, cert_pem)
VALUES
  (1, @key_enc, @cert_pem)
ON CONFLICT (id) DO UPDATE
SET
  key_enc = saml_keypair.key_enc,
  cert_pem = saml_keypair.cert_pem
RETURNING
  key_enc,
  cert_pem;
