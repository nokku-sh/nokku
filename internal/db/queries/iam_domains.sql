-- name: UpsertWorkspaceDomain :one
INSERT INTO
  workspace_domains (workspace_id, domain, token, verified_at, verified_until)
VALUES
  (@workspace_id, @domain, @token, NULL, NULL)
ON CONFLICT (domain) DO UPDATE
SET
  workspace_id = EXCLUDED.workspace_id,
  token = EXCLUDED.token,
  verified_at = NULL,
  verified_until = NULL,
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
  AND verified_at IS NOT NULL
  AND (
    verified_until IS NULL
    OR verified_until > NOW()
  );

-- name: ListVerifiedDomainsForProvider :many
SELECT
  *
FROM
  workspace_domains
WHERE
  provider_id = @provider_id
  AND verified_at IS NOT NULL
  AND (
    verified_until IS NULL
    OR verified_until > @verified_now
  );

-- name: VerifyWorkspaceDomain :exec
UPDATE workspace_domains
SET
  verified_at = @verified_at,
  verified_until = @verified_until,
  updated_at = NOW()
WHERE
  workspace_id = @workspace_id
  AND domain = @domain;

-- name: DeleteWorkspaceDomain :exec
DELETE FROM workspace_domains
WHERE
  workspace_id = @workspace_id
  AND domain = @domain;
