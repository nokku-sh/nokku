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

-- name: WorkspaceOwnsVerifiedDomain :one
SELECT EXISTS (
  SELECT
    1
  FROM
    workspace_domains
  WHERE
    workspace_id = @workspace_id
    AND domain = @domain
    AND verified_at IS NOT NULL
)::BOOLEAN AS owns_domain;

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
  is_active = COALESCE(sqlc.narg('is_active'), is_active),
  enforce_sso = COALESCE(sqlc.narg('enforce_sso'), enforce_sso),
  allow_jit_provisioning = COALESCE(sqlc.narg('allow_jit_provisioning'), allow_jit_provisioning)
WHERE
  workspace_id = @workspace_id
RETURNING
  *;

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
