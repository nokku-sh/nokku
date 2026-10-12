-- name: CreateCA :one
-- Every setting comes from the caller, ssh.NewCA fills in what a new CA starts with.
INSERT INTO
  ssh_cas (
    name,
    description,
    private_key,
    public_key,
    not_before,
    not_after,
    key_type,
    key_bits,
    lifetime,
    user_default_ttl,
    user_max_ttl,
    force_command,
    source_address,
    host_default_ttl,
    host_max_ttl,
    allowed_key_types
  )
VALUES
  (
    @name,
    @description,
    @private_key,
    @public_key,
    @not_before,
    @not_after,
    @key_type,
    @key_bits,
    @lifetime,
    @user_default_ttl,
    @user_max_ttl,
    @force_command,
    @source_address,
    @host_default_ttl,
    @host_max_ttl,
    @allowed_key_types
  )
RETURNING
  *;

-- name: GetCA :one
SELECT
  *
FROM
  ssh_cas
WHERE
  id = @ca_id;

-- name: GetCAForUpdate :one
SELECT
  *
FROM
  ssh_cas
WHERE
  id = @ca_id
FOR UPDATE;

-- name: GetCAByDaemonID :one
SELECT
  ca.*
FROM
  ssh_cas ca
  JOIN targets t ON t.ca_id = ca.id
WHERE
  t.daemon_id = $1;

-- name: GetDaemonCAKeys :one
-- The public half only. A daemon sync must not decrypt the private key.
SELECT
  ca.public_key,
  ca.previous_public_key,
  ca.previous_trusted_until
FROM
  ssh_cas ca
  JOIN targets t ON t.ca_id = ca.id
WHERE
  t.daemon_id = $1;

-- name: GetCAsByIDs :many
SELECT
  id,
  workspace_id,
  name,
  public_key,
  is_default,
  user_default_ttl,
  user_max_ttl
FROM
  ssh_cas
WHERE
  id = ANY (sqlc.arg('ca_ids')::UUID[]);

-- name: ListCAs :many
SELECT
  *
FROM
  ssh_cas
ORDER BY
  id ASC;

-- name: UpdateCA :one
UPDATE ssh_cas
SET
  name = COALESCE(sqlc.narg('name'), name),
  description = COALESCE(sqlc.narg('description'), description),
  is_active = COALESCE(sqlc.narg('is_active'), is_active),
  lifetime = COALESCE(sqlc.narg('lifetime'), lifetime),
  user_default_ttl = COALESCE(sqlc.narg('user_default_ttl'), user_default_ttl),
  user_max_ttl = COALESCE(sqlc.narg('user_max_ttl'), user_max_ttl),
  force_command = COALESCE(sqlc.narg('force_command'), force_command),
  source_address = COALESCE(sqlc.narg('source_address'), source_address),
  host_default_ttl = COALESCE(sqlc.narg('host_default_ttl'), host_default_ttl),
  host_max_ttl = COALESCE(sqlc.narg('host_max_ttl'), host_max_ttl),
  allowed_key_types = COALESCE(sqlc.narg('allowed_key_types'), allowed_key_types),
  updated_at = NOW()
WHERE
  id = @ca_id
RETURNING
  *;

-- The replaced key stays trusted for as long as a certificate it signed can live, unless revoke_previous drops it.
-- name: ReplaceCA :one
UPDATE ssh_cas
SET
  previous_public_key = CASE
    WHEN @revoke_previous::BOOLEAN THEN NULL
    ELSE public_key
  END,
  previous_trusted_until = CASE
    WHEN @revoke_previous::BOOLEAN THEN NULL
    ELSE NOW() + user_max_ttl
  END,
  private_key = @private_key,
  public_key = @public_key,
  not_before = @not_before,
  not_after = @not_after,
  key_type = @key_type,
  key_bits = @key_bits,
  updated_at = NOW()
WHERE
  id = @ca_id
RETURNING
  *;

-- name: SetDefaultCA :exec
-- One statement, so the partial unique index never sees two defaults.
UPDATE ssh_cas
SET
  is_default = (id = @ca_id),
  updated_at = NOW()
WHERE
  id = @ca_id
  OR is_default;

-- name: DeleteCA :one
DELETE FROM ssh_cas
WHERE
  id = @ca_id
RETURNING
  *;

-- skip_ids holds CAs whose rotation already failed this pass.
-- name: GetExpiringCAForUpdate :one
SELECT
  ca.*
FROM
  ssh_cas ca
WHERE
  ca.is_active = TRUE
  AND ca.id <> ALL (COALESCE(@skip_ids::UUID[], '{}'))
  AND NOW() BETWEEN ca.not_before AND ca.not_after
  AND EXTRACT(
    EPOCH
    FROM
      (NOW() - ca.not_before)
  ) / EXTRACT(
    EPOCH
    FROM
      (ca.not_after - ca.not_before)
  ) >= 0.80::DOUBLE PRECISION
ORDER BY
  ca.not_after ASC
LIMIT
  1
FOR UPDATE
  SKIP LOCKED;
