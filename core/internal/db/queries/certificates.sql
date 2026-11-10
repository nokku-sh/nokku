-- name: CreateCA :one
-- Every setting comes from the caller, ssh.NewCA fills in what a new CA starts with. ssh.CreateCA adds the keys.
INSERT INTO
  ssh_cas (
    user_public_key,
    host_public_key,
    user_ttl
  )
VALUES
  (
    @user_public_key,
    @host_public_key,
    @user_ttl
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
      ELSE c.user_public_key
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

-- name: GetWorkspaceCAForShare :one
-- A sync report holds a rollover back until it commits.
SELECT
  *
FROM
  ssh_cas
WHERE
  workspace_id = current_workspace_id ()
FOR SHARE;

-- name: UpdateCA :one
UPDATE ssh_cas
SET
  user_ttl = COALESCE(sqlc.narg('user_ttl'), user_ttl),
  source_address = COALESCE(sqlc.narg('source_address'), source_address),
  updated_at = NOW()
WHERE
  workspace_id = current_workspace_id ()
RETURNING
  *;

-- name: ReplaceCA :one
-- Nothing keeps the old keys. clock_timestamp is after any sync report that held the row.
UPDATE ssh_cas
SET
  user_public_key = @user_public_key,
  host_public_key = @host_public_key,
  rotated_at = clock_timestamp(),
  updated_at = NOW()
WHERE
  id = @ca_id
RETURNING
  *;
