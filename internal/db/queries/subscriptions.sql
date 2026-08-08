-- name: GetSubscription :one
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
-- Records which Stripe customer a workspace maps to, so checkout always reuses
-- the same customer. Status stays inactive so this row never grants
-- entitlements on its own; the webhook promotes it to a real subscription.
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
-- Note: source is only overwritten when the row is provider-managed ('stripe')
-- or empty, so manual subscriptions survive provider syncs.
INSERT INTO
  workspace_subscriptions (
    workspace_id,
    source,
    plan,
    status,
    customer_id,
    subscription_id,
    current_period_end,
    cancel_at_period_end
  )
VALUES
  ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (workspace_id) DO UPDATE
SET
  source = EXCLUDED.source,
  plan = EXCLUDED.plan,
  status = EXCLUDED.status,
  customer_id = EXCLUDED.customer_id,
  subscription_id = EXCLUDED.subscription_id,
  current_period_end = EXCLUDED.current_period_end,
  cancel_at_period_end = EXCLUDED.cancel_at_period_end
WHERE
  workspace_subscriptions.source IN ('stripe', '');

-- name: ListActiveSubscriptions :many
SELECT
  *
FROM
  workspace_subscriptions
WHERE
  status = ANY (@statuses::TEXT[])
  AND source = ANY (@sources::TEXT[]);

-- name: ListProviderSubscriptions :many
SELECT
  *
FROM
  workspace_subscriptions
WHERE
  source = ANY (@sources::TEXT[]);

-- name: GetWorkspaceStats :one
SELECT
  (
    SELECT
      COUNT(*)
    FROM
      workspace_members wm
    WHERE
      wm.workspace_id = @workspace_id
  ) AS member_count,
  (
    SELECT
      COUNT(*)
    FROM
      teams t
    WHERE
      t.workspace_id = @workspace_id
  ) AS team_count,
  (
    SELECT
      COUNT(*)
    FROM
      targets tg
    WHERE
      tg.workspace_id = @workspace_id
  ) AS target_count,
  (
    SELECT
      COUNT(*)
    FROM
      certificate_authorities ca
    WHERE
      ca.workspace_id = @workspace_id
  ) AS ca_count,
  (
    SELECT
      COUNT(*)
    FROM
      service_accounts sa
    WHERE
      sa.workspace_id = @workspace_id
  ) AS service_account_count;
