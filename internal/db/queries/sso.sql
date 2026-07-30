-- OAuth Identities -----------------------------------------------------------
-- name: GetOAuthIdentity :one
SELECT
  *
FROM
  oauth_identities
WHERE
  provider_id = @provider_id
  AND provider = @provider;

-- name: GetOAuthIdentitiesByProvider :many
SELECT
  o.*,
  u.email,
  u.username,
  u.name
FROM
  oauth_identities o
  JOIN users u ON u.id = o.user_id
WHERE
  o.provider = @provider
ORDER BY
  o.created_at DESC;

-- name: UpsertOAuthIdentity :one
INSERT INTO
  oauth_identities (provider_id, provider, user_id, provider_email, provider_username)
VALUES
  (@provider_id, @provider, @user_id, @provider_email, @provider_username)
ON CONFLICT (provider_id, provider) DO UPDATE
SET
  provider_email = EXCLUDED.provider_email,
  provider_username = EXCLUDED.provider_username
RETURNING
  *;

-- name: GetOAuthIdentitiesByUserID :many
SELECT
  *
FROM
  oauth_identities
WHERE
  user_id = @user_id
ORDER BY
  created_at DESC;

-- name: DeleteOAuthIdentity :exec
DELETE FROM oauth_identities
WHERE
  provider_id = @provider_id
  AND provider = @provider;

-- name: DeleteOAuthIdentityByUser :exec
DELETE FROM oauth_identities
WHERE
  user_id = @user_id
  AND provider = @provider;

-- Passkeys -------------------------------------------------------------------
-- name: CreatePasskey :exec
INSERT INTO
  passkeys (
    id,
    user_id,
    public_key,
    attestation_type,
    aaguid,
    sign_count,
    transports,
    backup_eligible,
    backup_state,
    name
  )
VALUES
  (
    @id,
    @user_id,
    @public_key,
    @attestation_type,
    @aaguid,
    @sign_count,
    @transports,
    @backup_eligible,
    @backup_state,
    @name
  );

-- name: GetPasskey :one
SELECT
  *
FROM
  passkeys
WHERE
  id = @passkey_id;

-- name: GetPasskeysByUserID :many
SELECT
  *
FROM
  passkeys
WHERE
  user_id = @user_id;

-- name: UpdatePasskeySignCount :exec
UPDATE passkeys
SET
  sign_count = @sign_count
WHERE
  id = @passkey_id;

-- name: UpdatePasskeyLastUsed :exec
UPDATE passkeys
SET
  last_used_at = @last_used_at
WHERE
  id = @passkey_id;

-- name: UpdatePasskeyName :exec
UPDATE passkeys
SET
  name = @name
WHERE
  id = @passkey_id;

-- name: DeletePasskey :exec
DELETE FROM passkeys
WHERE
  id = @passkey_id;

-- OIDC Providers -------------------------------------------------------------
-- name: GetOIDCProvider :one
SELECT
  *
FROM
  oidc_providers
WHERE
  workspace_id = @workspace_id;

-- name: GetOIDCProviderByID :one
SELECT
  p.*
FROM
  oidc_providers p
  JOIN workspace_domains wd ON wd.workspace_id = p.workspace_id
WHERE
  p.workspace_id = @workspace_id
  AND p.is_active = TRUE
  AND wd.verified_at IS NOT NULL;

-- name: GetOIDCProviderByDomain :one
SELECT
  p.*
FROM
  oidc_providers p
  JOIN workspace_domains wd ON wd.workspace_id = p.workspace_id
WHERE
  wd.domain = @domain
  AND p.is_active = TRUE
  AND wd.verified_at IS NOT NULL;

-- name: UpdateOIDCProvider :one
UPDATE oidc_providers
SET
  name = COALESCE(sqlc.narg('name'), name),
  issuer_url = COALESCE(sqlc.narg('issuer_url'), issuer_url),
  client_id = COALESCE(sqlc.narg('client_id'), client_id),
  client_secret = COALESCE(sqlc.narg('client_secret'), client_secret),
  scopes = COALESCE(sqlc.narg('scopes'), scopes),
  email_claim = COALESCE(sqlc.narg('email_claim'), email_claim),
  name_claim = COALESCE(sqlc.narg('name_claim'), name_claim),
  username_claim = COALESCE(sqlc.narg('username_claim'), username_claim),
  picture_claim = COALESCE(sqlc.narg('picture_claim'), picture_claim),
  is_active = COALESCE(sqlc.narg('is_active'), is_active),
  enforce_sso = COALESCE(sqlc.narg('enforce_sso'), enforce_sso),
  allow_jit_provisioning = COALESCE(sqlc.narg('allow_jit_provisioning'), allow_jit_provisioning),
  use_pkce = COALESCE(sqlc.narg('use_pkce'), use_pkce)
WHERE
  workspace_id = @workspace_id
RETURNING
  *;

-- SAML Providers ---------------------------------------------------------------
-- name: GetSAMLProvider :one
SELECT
  *
FROM
  saml_providers
WHERE
  workspace_id = @workspace_id;

-- name: GetSAMLProviderByID :one
SELECT
  p.*
FROM
  saml_providers p
  JOIN workspace_domains wd ON wd.workspace_id = p.workspace_id
WHERE
  p.workspace_id = @workspace_id
  AND p.is_active = TRUE
  AND wd.verified_at IS NOT NULL;

-- name: GetSAMLProviderByDomain :one
SELECT
  p.*
FROM
  saml_providers p
  JOIN workspace_domains wd ON wd.workspace_id = p.workspace_id
WHERE
  wd.domain = @domain
  AND p.is_active = TRUE
  AND wd.verified_at IS NOT NULL;

-- name: UpdateSAMLProvider :one
UPDATE saml_providers
SET
  name = COALESCE(sqlc.narg('name'), name),
  metadata_url = COALESCE(sqlc.narg('metadata_url'), metadata_url),
  email_attribute = COALESCE(sqlc.narg('email_attribute'), email_attribute),
  name_attribute = COALESCE(sqlc.narg('name_attribute'), name_attribute),
  username_attribute = COALESCE(sqlc.narg('username_attribute'), username_attribute),
  picture_attribute = COALESCE(sqlc.narg('picture_attribute'), picture_attribute),
  sp_private_key = COALESCE(sqlc.narg('sp_private_key'), sp_private_key),
  sp_certificate = COALESCE(sqlc.narg('sp_certificate'), sp_certificate),
  sp_cert_expires_at = COALESCE(sqlc.narg('sp_cert_expires_at'), sp_cert_expires_at),
  is_active = COALESCE(sqlc.narg('is_active'), is_active),
  enforce_sso = COALESCE(sqlc.narg('enforce_sso'), enforce_sso),
  allow_jit_provisioning = COALESCE(sqlc.narg('allow_jit_provisioning'), allow_jit_provisioning)
WHERE
  workspace_id = @workspace_id
RETURNING
  *;

-- name: GetExpiringSAMLProviderForUpdate :one
SELECT
  *
FROM
  saml_providers
WHERE
  is_active = TRUE
  AND sp_cert_expires_at IS NOT NULL
  AND sp_cert_expires_at < NOW() + INTERVAL '30 days'
ORDER BY
  sp_cert_expires_at ASC
LIMIT
  1
FOR UPDATE
  SKIP LOCKED;

-- name: CheckDomainSSOEnforcement :one
SELECT
  EXISTS (
    SELECT
      1
    FROM
      workspace_domains wd
      LEFT JOIN oidc_providers op ON op.workspace_id = wd.workspace_id
      AND op.is_active = TRUE
      LEFT JOIN saml_providers sp ON sp.workspace_id = wd.workspace_id
      AND sp.is_active = TRUE
    WHERE
      wd.domain = @domain
      AND wd.verified_at IS NOT NULL
      AND (
        (
          op.workspace_id IS NOT NULL
          AND op.enforce_sso = TRUE
        )
        OR (
          sp.workspace_id IS NOT NULL
          AND sp.enforce_sso = TRUE
        )
      )
  )::BOOLEAN AS enforce_sso;
