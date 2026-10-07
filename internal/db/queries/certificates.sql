-- name: CreateCA :one
INSERT INTO
  certificate_authorities (
    name,
    description,
    certificate,
    private_key,
    public_key,
    serial_number,
    subject,
    is_default,
    not_before,
    not_after,
    key_type,
    authority_type,
    key_bits,
    lifetime,
    user_default_ttl,
    user_max_ttl,
    user_extensions,
    user_critical_options,
    host_default_ttl,
    host_max_ttl,
    allowed_key_types
  )
VALUES
  (
    @name,
    @description,
    @certificate,
    @private_key,
    @public_key,
    @serial_number,
    @subject,
    @is_default,
    @not_before,
    @not_after,
    COALESCE(sqlc.narg('key_type'), 3),
    COALESCE(sqlc.narg('authority_type'), 1),
    @key_bits,
    COALESCE(sqlc.narg('lifetime'), '8760 hours'::interval),
    COALESCE(sqlc.narg('user_default_ttl'), '120 hours'::interval),
    COALESCE(sqlc.narg('user_max_ttl'), '168 hours'::interval),
    COALESCE(sqlc.narg('user_extensions'), '{"permit-pty": "", "permit-user-rc": "", "permit-port-forwarding": "", "permit-agent-forwarding": ""}'::jsonb),
    COALESCE(sqlc.narg('user_critical_options'), '{}'::jsonb),
    COALESCE(sqlc.narg('host_default_ttl'), '2160 hours'::interval),
    COALESCE(sqlc.narg('host_max_ttl'), '4320 hours'::interval),
    COALESCE(sqlc.narg('allowed_key_types'), ARRAY[1, 2, 3])
  )
RETURNING
  *;

-- name: GetCA :one
SELECT
  *
FROM
  certificate_authorities
WHERE
  id = @ca_id;

-- name: GetCAForUpdate :one
SELECT
  *
FROM
  certificate_authorities
WHERE
  id = @ca_id
FOR UPDATE;

-- name: GetDefaultCA :one
SELECT
  *
FROM
  certificate_authorities
WHERE
  authority_type = @authority_type
  AND is_default = TRUE
  AND is_active = TRUE
  AND NOW() BETWEEN not_before AND not_after;

-- name: GetCAByDaemonID :one
SELECT
  ca.*
FROM
  certificate_authorities ca
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
  certificate_authorities ca
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
  authority_type,
  certificate,
  user_default_ttl,
  user_max_ttl
FROM
  certificate_authorities
WHERE
  id = ANY (sqlc.arg('ca_ids')::UUID[]);

-- name: ListCAs :many
SELECT
  *
FROM
  certificate_authorities
WHERE
  (
    sqlc.narg('name_query')::text IS NULL
    OR name ILIKE '%' || sqlc.narg('name_query') || '%'
  )
  AND (
    sqlc.narg('is_active')::boolean IS NULL
    OR is_active = sqlc.narg('is_active')
  )
  AND (
    sqlc.narg('is_default')::boolean IS NULL
    OR is_default = sqlc.narg('is_default')
  )
  AND (
    sqlc.narg('key_type')::integer IS NULL
    OR key_type = sqlc.narg('key_type')
  )
  AND (
    sqlc.narg('status_filter')::text IS NULL
    OR (
      sqlc.narg('status_filter') = 'valid'
      AND NOW() BETWEEN not_before AND not_after
    )
    OR (
      sqlc.narg('status_filter') = 'expired'
      AND NOW() > not_after
    )
    OR (
      sqlc.narg('status_filter') = 'future'
      AND NOW() < not_before
    )
  )
ORDER BY
  id ASC
LIMIT
  sqlc.narg('limit')
OFFSET
  sqlc.narg('offset');

-- name: UpdateCA :one
UPDATE certificate_authorities
SET
  name = COALESCE(sqlc.narg('name'), name),
  description = COALESCE(sqlc.narg('description'), description),
  is_active = COALESCE(sqlc.narg('is_active'), is_active),
  is_default = COALESCE(sqlc.narg('is_default'), is_default),
  lifetime = COALESCE(sqlc.narg('lifetime'), lifetime),
  user_default_ttl = COALESCE(sqlc.narg('user_default_ttl'), user_default_ttl),
  user_max_ttl = COALESCE(sqlc.narg('user_max_ttl'), user_max_ttl),
  user_extensions = COALESCE(sqlc.narg('user_extensions'), user_extensions),
  user_critical_options = COALESCE(sqlc.narg('user_critical_options'), user_critical_options),
  host_default_ttl = COALESCE(sqlc.narg('host_default_ttl'), host_default_ttl),
  host_max_ttl = COALESCE(sqlc.narg('host_max_ttl'), host_max_ttl),
  allowed_key_types = COALESCE(sqlc.narg('allowed_key_types'), allowed_key_types)
WHERE
  id = @ca_id
RETURNING
  *;

-- The replaced key stays trusted for as long as a certificate it signed can
-- live, unless revoke_previous drops it at once.
-- name: ReplaceCA :one
UPDATE certificate_authorities
SET
  previous_public_key = CASE
    WHEN @revoke_previous::BOOLEAN THEN NULL
    ELSE public_key
  END,
  previous_trusted_until = CASE
    WHEN @revoke_previous::BOOLEAN THEN NULL
    ELSE NOW() + user_max_ttl
  END,
  certificate = @certificate,
  private_key = @private_key,
  public_key = @public_key,
  serial_number = @serial_number,
  subject = @subject,
  not_before = @not_before,
  not_after = @not_after,
  key_type = @key_type,
  key_bits = @key_bits
WHERE
  id = @ca_id
RETURNING
  *;

-- The enforce_single_default_ca trigger clears the previous default.
-- name: DeleteCA :one
DELETE FROM certificate_authorities
WHERE
  id = @ca_id
RETURNING
  *;

-- skip_ids holds CAs whose rotation already failed this pass.
-- name: GetExpiringCAForUpdate :one
SELECT
  ca.*
FROM
  certificate_authorities ca
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
