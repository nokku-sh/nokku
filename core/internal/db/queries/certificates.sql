-- name: CreateCA :one
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

-- name: PutCAKeys :exec
INSERT INTO
  ssh_ca_keys (user_private_key, host_private_key)
VALUES
  (@user_private_key, @host_private_key)
ON CONFLICT (workspace_id) DO UPDATE
SET
  user_private_key = EXCLUDED.user_private_key,
  host_private_key = EXCLUDED.host_private_key;

-- name: GetCASigningKeys :one
SELECT
  sqlc.embed(c),
  k.user_private_key,
  k.host_private_key
FROM
  ssh_ca_keys k
  JOIN ssh_cas c ON c.workspace_id = k.workspace_id
WHERE
  k.workspace_id = current_workspace_id ();

-- name: GetWorkspaceCA :one
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
  workspace_id = current_workspace_id ()
RETURNING
  *;
