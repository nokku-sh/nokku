-- name: UpsertWorkspaceDomain :one
INSERT INTO
  workspace_domains (workspace_id, domain, verified_at)
VALUES
  (@workspace_id, @domain, NULL)
ON CONFLICT (workspace_id, domain) DO UPDATE
SET
  token = encode(gen_random_bytes (16), 'hex'),
  verified_at = NULL,
  updated_at = NOW()
RETURNING
  *;

-- name: GetWorkspaceDomain :one
SELECT
  *
FROM
  workspace_domains
WHERE
  workspace_id = @workspace_id
  AND domain = @domain;

-- name: ListWorkspaceDomains :many
SELECT
  *
FROM
  workspace_domains
WHERE
  workspace_id = @workspace_id
ORDER BY
  domain ASC;

-- name: GetVerifiedWorkspaceDomain :one
SELECT
  *
FROM
  workspace_domains
WHERE
  domain = @domain
  AND verified_at IS NOT NULL;

-- name: VerifyWorkspaceDomain :one
WITH
  verified AS (
    UPDATE workspace_domains wd
    SET
      verified_at = NOW()
    WHERE
      wd.workspace_id = @workspace_id
      AND wd.domain = @domain
      AND wd.token = @token
    RETURNING
      *
  ),
  evicted AS (
    DELETE FROM workspace_domains wd USING verified v
    WHERE
      wd.domain = v.domain
      AND wd.workspace_id != @workspace_id
  )
SELECT
  *
FROM
  verified;

-- name: DeleteWorkspaceDomain :exec
DELETE FROM workspace_domains
WHERE
  workspace_id = @workspace_id
  AND domain = @domain;
