-- name: GetSubscription :one
-- The queries here name the workspace, billing and the plan lookup run as nokku_system.
SELECT
  *
FROM
  workspace_subscriptions
WHERE
  workspace_id = $1;

-- name: UpsertSubscription :exec
-- Manual subscriptions survive provider syncs, a trial gives way to the first one.
INSERT INTO
  workspace_subscriptions (
    workspace_id,
    source,
    plan,
    status,
    customer_id,
    subscription_id,
    current_period_end,
    cancel_at_period_end,
    seats,
    ended_at
  )
VALUES
  ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (workspace_id) DO UPDATE
SET
  source = EXCLUDED.source,
  plan = EXCLUDED.plan,
  status = EXCLUDED.status,
  customer_id = EXCLUDED.customer_id,
  subscription_id = EXCLUDED.subscription_id,
  current_period_end = EXCLUDED.current_period_end,
  cancel_at_period_end = EXCLUDED.cancel_at_period_end,
  seats = EXCLUDED.seats,
  ended_at = EXCLUDED.ended_at,
  -- A plan that ends again is a new countdown, the warnings of the last one do not count.
  deletion_warning = CASE
    WHEN workspace_subscriptions.ended_at IS DISTINCT FROM EXCLUDED.ended_at THEN 0
    ELSE workspace_subscriptions.deletion_warning
  END,
  deletion_warned_at = CASE
    WHEN workspace_subscriptions.ended_at IS DISTINCT FROM EXCLUDED.ended_at THEN NULL
    ELSE workspace_subscriptions.deletion_warned_at
  END,
  updated_at = NOW()
WHERE
  workspace_subscriptions.source IN ('stripe', 'trial', '');

-- name: ListProviderSubscriptions :many
-- Ended subscriptions are final at the provider, so they need no more syncs.
SELECT
  *
FROM
  workspace_subscriptions
WHERE
  source = 'stripe'
  AND subscription_id <> ''
  AND ended_at IS NULL;

-- name: GetInstanceLicense :one
SELECT
  key
FROM
  instance_license
WHERE
  id = 1;

-- name: SetInstanceLicense :exec
INSERT INTO
  instance_license (id, key)
VALUES
  (1, @key)
ON CONFLICT (id) DO UPDATE
SET
  key = EXCLUDED.key,
  updated_at = NOW();

-- name: CountWorkspaceResources :one
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
    ) + (
      SELECT
        COUNT(*)
      FROM
        ssh_cas ca
      WHERE
        ca.workspace_id = $1
    ) + (
      SELECT
        COUNT(*)
      FROM
        daemons d
      WHERE
        d.workspace_id = $1
    )
  )::bigint AS resource_count;

-- name: ListTrialsEnding :many
-- Trials that end within the next days, with the owner to remind. Runs as nokku_system.
SELECT
  s.workspace_id,
  s.current_period_end::timestamptz AS trial_end,
  s.trial_reminder,
  w.slug,
  w.name AS workspace_name,
  u.id AS owner_id,
  u.email AS owner_email
FROM
  workspace_subscriptions s
  JOIN workspaces w ON w.id = s.workspace_id
  JOIN users u ON u.workspace_id = s.workspace_id
  AND u.role = 5 -- owner
  AND u.active
WHERE
  s.source = 'trial'
  AND s.current_period_end > NOW()
  AND s.current_period_end <= NOW() + make_interval(days => @within::int);

-- name: SetTrialReminder :exec
UPDATE workspace_subscriptions
SET
  trial_reminder = @days,
  updated_at = NOW()
WHERE
  workspace_id = @workspace_id
  AND source = 'trial';

-- name: ListLapsedWorkspaces :many
-- Hosted workspaces whose trial or paid plan is over, with the owner to warn. deletionDate in internal/api decides when
-- each goes. Runs as nokku_system.
SELECT
  sqlc.embed(s),
  w.slug,
  w.name AS workspace_name,
  u.id AS owner_id,
  u.email AS owner_email
FROM
  workspace_subscriptions s
  JOIN workspaces w ON w.id = s.workspace_id
  LEFT JOIN users u ON u.workspace_id = s.workspace_id
  AND u.role = 5 -- owner
  AND u.active
WHERE
  (
    s.source = 'trial'
    AND s.current_period_end < NOW()
  )
  OR (
    s.source = 'stripe'
    AND s.ended_at IS NOT NULL
  );

-- name: SetDeletionWarning :exec
UPDATE workspace_subscriptions
SET
  deletion_warning = @days,
  deletion_warned_at = NOW(),
  updated_at = NOW()
WHERE
  workspace_id = @workspace_id;
