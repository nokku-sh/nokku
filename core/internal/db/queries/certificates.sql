-- name: CreateCA :one
-- Every setting comes from the caller, ssh.NewCA fills in what a new CA starts with.
INSERT INTO
  ssh_cas (
    name,
    description,
    private_key,
    public_key,
    host_private_key,
    host_public_key,
    user_default_ttl,
    user_max_ttl,
    force_command,
    source_address,
    host_default_ttl,
    host_max_ttl
  )
VALUES
  (
    @name,
    @description,
    @private_key,
    @public_key,
    @host_private_key,
    @host_public_key,
    @user_default_ttl,
    @user_max_ttl,
    @force_command,
    @source_address,
    @host_default_ttl,
    @host_max_ttl
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
-- The public halves only. A daemon sync must not decrypt a private key.
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
-- The public halves only, for clients to trust.
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
  is_active = COALESCE(sqlc.narg('is_active'), is_active),
  user_default_ttl = COALESCE(sqlc.narg('user_default_ttl'), user_default_ttl),
  user_max_ttl = COALESCE(sqlc.narg('user_max_ttl'), user_max_ttl),
  force_command = COALESCE(sqlc.narg('force_command'), force_command),
  source_address = COALESCE(sqlc.narg('source_address'), source_address),
  host_default_ttl = COALESCE(sqlc.narg('host_default_ttl'), host_default_ttl),
  host_max_ttl = COALESCE(sqlc.narg('host_max_ttl'), host_max_ttl),
  updated_at = NOW()
WHERE
  id = @ca_id
RETURNING
  *;

-- The replaced user key stays trusted for as long as a certificate it signed can live, unless revoke_previous drops
-- it. The replaced host key gets the same time, a daemon asks for a new host certificate at its next sync.
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
  private_key = @private_key,
  public_key = @public_key,
  host_private_key = @host_private_key,
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
