-- name: GetKeysetData :one
SELECT
  data
FROM
  keysets
WHERE
  id = 1;

-- name: InsertKeyset :execrows
INSERT INTO
  keysets (id, data)
VALUES
  (1, @data)
ON CONFLICT (id) DO NOTHING;

-- name: UpdateKeysetWrappedData :execrows
UPDATE keysets
SET
  data = @data,
  updated_at = NOW()
WHERE
  id = 1;

-- name: UpsertKeysetWrappedData :exec
-- Rotation-only (rotate-secrets command): persist the target keyset
-- atomically within the rotation transaction. Never used on the boot path.
INSERT INTO
  keysets (id, data)
VALUES
  (1, @data)
ON CONFLICT (id) DO UPDATE
SET
  data = @data,
  updated_at = NOW();

-- name: TrySecretRotationLock :one
SELECT
  pg_try_advisory_xact_lock(hashtext ('global-secret-rotation'));

-- name: GetEncryptedCAKeys :many
SELECT
  id,
  private_key
FROM
  certificate_authorities
WHERE
  private_key IS NOT NULL;

-- name: UpdateCAPrivateKey :exec
UPDATE certificate_authorities
SET
  private_key = @private_key
WHERE
  id = @id;

