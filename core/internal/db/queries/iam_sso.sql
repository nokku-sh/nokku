-- name: UpsertSSOProvider :one
INSERT INTO
  sso_providers (provider_id, name, enabled, config)
VALUES
  (@provider_id, @name, @enabled, @config)
ON CONFLICT (workspace_id, provider_id) DO UPDATE
SET
  name = EXCLUDED.name,
  enabled = EXCLUDED.enabled,
  config = EXCLUDED.config,
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

-- name: ListSSOProviders :many
SELECT
  *
FROM
  sso_providers
ORDER BY
  created_at ASC;

-- name: DeleteSSOProvider :execrows
DELETE FROM sso_providers
WHERE
  provider_id = @provider_id;

-- name: HasSSOSignIn :one
SELECT
  EXISTS (
    SELECT
      1
    FROM
      credentials c
      JOIN sso_providers p ON p.workspace_id = c.workspace_id
      AND p.provider_id = c.provider
    WHERE
      c.type = 'oidc'
      AND p.enabled
  );
