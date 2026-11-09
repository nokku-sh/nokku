-- name: GetLicense :one
-- The queries here name the workspace, the plan lookup and the jobs run as nokku_system.
SELECT
  *
FROM
  workspace_licenses
WHERE
  workspace_id = $1;

-- name: ListLicenses :many
-- The stored keys, for the daily refresh.
SELECT
  workspace_id,
  key
FROM
  workspace_licenses
WHERE
  key <> '';

-- name: SetLicense :exec
-- A key that ends at another time is a new countdown, the warnings of the last one do not count.
INSERT INTO
  workspace_licenses (workspace_id, key, license_id, ends_at)
VALUES
  (
    @workspace_id,
    @key,
    sqlc.narg('license_id'),
    sqlc.narg('ends_at')
  )
ON CONFLICT (workspace_id) DO UPDATE
SET
  key = EXCLUDED.key,
  license_id = EXCLUDED.license_id,
  ends_at = EXCLUDED.ends_at,
  deletion_warning = CASE
    WHEN workspace_licenses.ends_at IS DISTINCT FROM EXCLUDED.ends_at THEN 0
    ELSE workspace_licenses.deletion_warning
  END,
  deletion_warned_at = CASE
    WHEN workspace_licenses.ends_at IS DISTINCT FROM EXCLUDED.ends_at THEN NULL
    ELSE workspace_licenses.deletion_warned_at
  END,
  updated_at = NOW();

-- name: StartTrial :exec
-- A hosted workspace starts on a trial without a key, the first activated key replaces it.
INSERT INTO
  workspace_licenses (workspace_id, ends_at)
VALUES
  (
    @workspace_id,
    NOW() + make_interval(days => @days::int)
  )
ON CONFLICT (workspace_id) DO NOTHING;

-- name: CountWorkspaceResources :one
-- A server counts once, its daemon is part of its target.
SELECT
  (
    (
      SELECT
        COUNT(*)
      FROM
        targets tg
      WHERE
        tg.workspace_id = $1
    ) + (
      SELECT
        COUNT(*)
      FROM
        teams t
      WHERE
        t.workspace_id = $1
    ) + (
      SELECT
        COUNT(*)
      FROM
        service_accounts sa
      WHERE
        sa.workspace_id = $1
    )
  )::bigint AS resource_count;

-- name: ListTrialsEnding :many
-- Trials that end within the next days, with the owner to remind. Runs as nokku_system.
SELECT
  s.workspace_id,
  s.ends_at::timestamptz AS trial_end,
  s.trial_reminder,
  w.slug,
  w.name AS workspace_name,
  u.id AS owner_id,
  u.email AS owner_email
FROM
  workspace_licenses s
  JOIN workspaces w ON w.id = s.workspace_id
  JOIN users u ON u.workspace_id = s.workspace_id
  AND u.role = 5 -- owner
  AND u.active
WHERE
  s.key = ''
  AND s.ends_at > NOW()
  AND s.ends_at <= NOW() + make_interval(days => @within::int);

-- name: SetTrialReminder :exec
UPDATE workspace_licenses
SET
  trial_reminder = @days,
  updated_at = NOW()
WHERE
  workspace_id = @workspace_id
  AND key = '';

-- name: ListLapsedWorkspaces :many
-- Hosted workspaces whose trial or key ran out, with the owner to warn. deletionDate in internal/api decides when each
-- goes. Runs as nokku_system.
SELECT
  sqlc.embed(s),
  w.slug,
  w.name AS workspace_name,
  u.id AS owner_id,
  u.email AS owner_email
FROM
  workspace_licenses s
  JOIN workspaces w ON w.id = s.workspace_id
  LEFT JOIN users u ON u.workspace_id = s.workspace_id
  AND u.role = 5 -- owner
  AND u.active
WHERE
  s.ends_at < NOW();

-- name: SetDeletionWarning :exec
UPDATE workspace_licenses
SET
  deletion_warning = @days,
  deletion_warned_at = NOW(),
  updated_at = NOW()
WHERE
  workspace_id = @workspace_id;
