-- name: CreateWorkspaceDomain :one
INSERT INTO
  workspace_domains (workspace_id, domain)
VALUES
  (@workspace_id, @domain)
RETURNING
  *;

-- name: GetWorkspaceDomain :one
SELECT
  *
FROM
  workspace_domains
WHERE
  domain = @domain;

-- name: ListWorkspaceDomains :many
SELECT
  *
FROM
  workspace_domains
WHERE
  workspace_id = @workspace_id
ORDER BY
  domain ASC;

-- name: CountVerifiedWorkspaceDomains :one
SELECT
  COUNT(*)::INTEGER
FROM
  workspace_domains
WHERE
  workspace_id = @workspace_id
  AND verified_at IS NOT NULL;

-- name: RegenerateVerificationToken :one
UPDATE workspace_domains
SET
  verification_token = encode(gen_random_bytes (16), 'hex'),
  verified_at = NULL
WHERE
  domain = @domain
RETURNING
  *;

-- name: VerifyWorkspaceDomain :one
WITH
  -- Delete this domain from any OTHER workspaces on verification
  evicted AS (
    DELETE FROM workspace_domains wd
    WHERE
      wd.domain = @domain
      AND wd.workspace_id != @workspace_id
  )
UPDATE workspace_domains wd
SET
  verified_at = NOW()
WHERE
  wd.domain = @domain
  AND wd.workspace_id = @workspace_id
  AND wd.verification_token = @token
  AND wd.verified_at IS NULL
RETURNING
  *;

-- name: VerifiedDomainExists :one
SELECT
  EXISTS (
    SELECT
      1
    FROM
      workspace_domains wd
    WHERE
      wd.domain = @domain
      AND wd.verified_at IS NOT NULL
  );

-- name: DeleteWorkspaceDomain :one
DELETE FROM workspace_domains
WHERE
  domain = @domain
RETURNING
  *;
