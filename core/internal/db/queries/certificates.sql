-- name: CreateCA :one
-- Every setting comes from the caller, ssh.NewCA fills in what a new CA starts with. ssh.CreateCA adds the keys.
INSERT INTO
  ssh_cas (
    name,
    description,
    public_key,
    host_public_key,
    user_default_ttl,
    user_max_ttl,
    force_command,
    source_address,
    host_ttl
  )
VALUES
  (
    @name,
    @description,
    @public_key,
    @host_public_key,
    @user_default_ttl,
    @user_max_ttl,
    @force_command,
    @source_address,
    @host_ttl
  )
RETURNING
  *;

-- name: PutCAKey :exec
-- Creating and rolling over a CA write its keys in the transaction that writes their public halves.
INSERT INTO
  ssh_ca_keys (ca_id, kind, private_key)
VALUES
  (@ca_id, @kind, @private_key)
ON CONFLICT (ca_id, kind) DO UPDATE
SET
  private_key = EXCLUDED.private_key;

-- name: GetCASigningKey :one
-- The one read of a CA private key, with the public key it must match. ssh.CASigner is its only caller.
SELECT
  k.workspace_id,
  k.ca_id,
  k.private_key,
  (
    CASE
      WHEN k.kind = 'host' THEN c.host_public_key
      ELSE c.public_key
    END
  )::TEXT AS public_key
FROM
  ssh_ca_keys k
  JOIN ssh_cas c ON c.id = k.ca_id
WHERE
  k.ca_id = @ca_id
  AND k.kind = @kind;

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
-- What a daemon trusts. Private keys live in ssh_ca_keys.
SELECT
  ca.public_key,
  ca.host_public_key,
  ca.previous_public_key,
  ca.previous_trusted_until
FROM
  ssh_cas ca
  JOIN targets t ON t.ca_id = ca.id
WHERE
  t.daemon_id = $1;

-- name: GetCAsByIDs :many
-- What clients trust.
SELECT
  id,
  workspace_id,
  name,
  public_key,
  host_public_key,
  previous_public_key,
  previous_host_public_key,
  previous_trusted_until,
  rotated_at,
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
  user_default_ttl = COALESCE(sqlc.narg('user_default_ttl'), user_default_ttl),
  user_max_ttl = COALESCE(sqlc.narg('user_max_ttl'), user_max_ttl),
  force_command = COALESCE(sqlc.narg('force_command'), force_command),
  source_address = COALESCE(sqlc.narg('source_address'), source_address),
  host_ttl = COALESCE(sqlc.narg('host_ttl'), host_ttl),
  updated_at = NOW()
WHERE
  id = @ca_id
RETURNING
  *;

-- The replaced user key stays trusted for as long as a certificate it signed can live, unless revoke_previous drops
-- it. The replaced host key gets the same time, a daemon asks for a new host certificate at its next sync. The
-- private keys go with PutCAKey in the same transaction.
-- name: ReplaceCA :one
UPDATE ssh_cas
SET
  previous_public_key = CASE
    WHEN @revoke_previous::BOOLEAN THEN NULL
    ELSE public_key
  END,
  previous_host_public_key = CASE
    WHEN @revoke_previous::BOOLEAN THEN NULL
    ELSE host_public_key
  END,
  previous_trusted_until = CASE
    WHEN @revoke_previous::BOOLEAN THEN NULL
    ELSE NOW() + user_max_ttl
  END,
  public_key = @public_key,
  host_public_key = @host_public_key,
  rotated_at = NOW(),
  updated_at = NOW()
WHERE
  id = @ca_id
RETURNING
  *;

-- name: ClearDefaultCA :exec
-- Runs before MarkDefaultCA. The partial unique index is checked row by row, so one statement that swaps
-- both can see two defaults. See Queries.SetDefaultCA.
UPDATE ssh_cas
SET
  is_default = FALSE,
  updated_at = NOW()
WHERE
  is_default
  AND id <> @ca_id;

-- name: MarkDefaultCA :exec
UPDATE ssh_cas
SET
  is_default = TRUE,
  updated_at = NOW()
WHERE
  id = @ca_id;

-- name: DeleteCA :one
DELETE FROM ssh_cas
WHERE
  id = @ca_id
RETURNING
  *;
