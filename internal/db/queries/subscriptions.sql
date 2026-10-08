-- name: GetSubscription :one
-- The queries here name the workspace, billing and the plan lookup run as
-- nokku_system.
SELECT
  *
FROM
  workspace_subscriptions
WHERE
  workspace_id = $1;

-- name: GetActiveSubscription :one
SELECT
  *
FROM
  workspace_subscriptions
WHERE
  workspace_id = $1
  AND status = ANY (@statuses::TEXT[])
  AND source = ANY (@sources::TEXT[]);

-- name: SetSubscriptionCustomer :exec
-- Status stays inactive so this row never grants entitlements until the
-- webhook promotes it.
INSERT INTO
  workspace_subscriptions (workspace_id, source, status, customer_id)
VALUES
  ($1, 'stripe', 'inactive', $2)
ON CONFLICT (workspace_id) DO UPDATE
SET
  source = 'stripe',
  status = 'inactive',
  customer_id = EXCLUDED.customer_id
WHERE
  workspace_subscriptions.source IN ('stripe', '');

-- name: UpsertSubscription :exec
-- Manual subscriptions survive provider syncs.
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
  updated_at = NOW()
WHERE
  workspace_subscriptions.source IN ('stripe', '');

-- name: ListProviderSubscriptions :many
-- Ended subscriptions are final at the provider, so they need no more syncs.
SELECT
  *
FROM
  workspace_subscriptions
WHERE
  source = ANY (@sources::TEXT[])
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
