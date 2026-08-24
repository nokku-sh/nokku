-- Shared SAML SP keypair (singleton) -----------------------------------------
-- name: GetSAMLSPKey :one
SELECT
  *
FROM
  saml_sp_keys
WHERE
  id = 1;

-- name: PutSAMLSPKey :one
INSERT INTO
  saml_sp_keys (id, private_key, certificate)
VALUES
  (1, @private_key, @certificate)
ON CONFLICT (id) DO UPDATE
SET
  id = EXCLUDED.id
RETURNING
  private_key,
  certificate;

-- name: GetEncryptedSAMLSPKey :one
SELECT
  private_key
FROM
  saml_sp_keys
WHERE
  id = 1;

-- name: UpdateSAMLSPPrivateKey :exec
UPDATE saml_sp_keys
SET
  private_key = @private_key
WHERE
  id = 1;
