-- name: SavePasskey :one
-- Keeps a label it has. A passkey never moves accounts, a clash returns no rows.
INSERT INTO
  passkeys (user_id, credential_id, data, label)
VALUES
  (@user_id, @credential_id, @data, @label)
ON CONFLICT (workspace_id, credential_id) DO UPDATE
SET
  data = EXCLUDED.data,
  label = COALESCE(NULLIF(passkeys.label, ''), EXCLUDED.label)
WHERE
  passkeys.user_id = EXCLUDED.user_id
RETURNING
  label;

-- name: ListPasskeys :many
SELECT
  *
FROM
  passkeys
WHERE
  user_id = @user_id
ORDER BY
  created_at ASC;

-- name: TouchPasskey :exec
UPDATE passkeys
SET
  last_used_at = NOW()
WHERE
  credential_id = @credential_id;

-- name: RenamePasskey :execrows
UPDATE passkeys
SET
  label = @label
WHERE
  user_id = @user_id
  AND id = @id;

-- name: LinkOIDCIdentity :one
-- An identity never moves accounts, a clash returns no rows.
INSERT INTO
  oidc_identities (user_id, provider_id, subject)
VALUES
  (@user_id, @provider_id, @subject)
ON CONFLICT (workspace_id, provider_id, subject) DO UPDATE
SET
  last_used_at = oidc_identities.last_used_at
WHERE
  oidc_identities.user_id = EXCLUDED.user_id
RETURNING
  id;

-- name: FindOIDCIdentity :one
SELECT
  *
FROM
  oidc_identities
WHERE
  provider_id = @provider_id
  AND subject = @subject;

-- name: TouchOIDCIdentity :exec
UPDATE oidc_identities
SET
  last_used_at = NOW()
WHERE
  id = @id;

-- name: DeleteUserOIDCIdentities :exec
DELETE FROM oidc_identities
WHERE
  user_id = @user_id;

-- name: DeleteOIDCIdentitiesByProvider :execrows
DELETE FROM oidc_identities
WHERE
  provider_id = @provider_id;

-- name: ListOIDCIdentities :many
SELECT
  *
FROM
  oidc_identities
WHERE
  user_id = @user_id
ORDER BY
  created_at ASC;

-- name: ListUserCredentialIDs :many
SELECT
  id
FROM
  passkeys
WHERE
  passkeys.user_id = @user_id
UNION ALL
SELECT
  id
FROM
  oidc_identities
WHERE
  oidc_identities.user_id = @user_id;

-- name: DeleteCredential :exec
WITH
  gone AS (
    DELETE FROM passkeys
    WHERE
      passkeys.user_id = @user_id
      AND passkeys.id = @id
  )
DELETE FROM oidc_identities
WHERE
  oidc_identities.user_id = @user_id
  AND oidc_identities.id = @id;

-- name: DeleteUserCredentials :exec
WITH
  gone AS (
    DELETE FROM passkeys
    WHERE
      passkeys.user_id = @user_id
  )
DELETE FROM oidc_identities
WHERE
  oidc_identities.user_id = @user_id;

-- name: DeleteUserCredentialsSince :exec
WITH
  gone AS (
    DELETE FROM passkeys
    WHERE
      passkeys.user_id = @user_id
      AND passkeys.created_at >= @since
  )
DELETE FROM oidc_identities
WHERE
  oidc_identities.user_id = @user_id
  AND oidc_identities.created_at >= @since;
