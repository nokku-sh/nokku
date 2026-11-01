-- name: CreateCA :one
-- Every setting comes from the caller, ssh.NewCA fills in what a new CA starts with. ssh.CreateCA adds the keys.
INSERT INTO
  ssh_cas (
    public_key,
    host_public_key,
    user_default_ttl,
    user_max_ttl,
    host_ttl
  )
VALUES
  (
    @public_key,
    @host_public_key,
    @user_default_ttl,
    @user_max_ttl,
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

-- name: GetWorkspaceCA :one
-- What signs and what is trusted in the workspace. Private keys live in ssh_ca_keys.
SELECT
  *
FROM
  ssh_cas
WHERE
  workspace_id = current_workspace_id ();

-- name: GetWorkspaceCAForUpdate :one
SELECT
  *
FROM
  ssh_cas
WHERE
  workspace_id = current_workspace_id ()
FOR UPDATE;

-- name: UpdateCA :one
UPDATE ssh_cas
SET
  user_default_ttl = COALESCE(sqlc.narg('user_default_ttl'), user_default_ttl),
  user_max_ttl = COALESCE(sqlc.narg('user_max_ttl'), user_max_ttl),
  source_address = COALESCE(sqlc.narg('source_address'), source_address),
  host_ttl = COALESCE(sqlc.narg('host_ttl'), host_ttl),
  updated_at = NOW()
WHERE
  workspace_id = current_workspace_id ()
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
