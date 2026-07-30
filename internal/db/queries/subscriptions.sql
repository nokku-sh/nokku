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

-- name: UpsertSubscription :exec
-- Note: overrides is intentionally NOT updated on conflict, manual overrides survive provider syncs.
INSERT INTO
  workspace_subscriptions (
    workspace_id,
    source,
    plan,
    status,
    customer_id,
    subscription_id,
    product_id,
    product_name,
    metadata,
    current_period_end,
    cancel_at_period_end
  )
VALUES
  ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (workspace_id) DO UPDATE
SET
  source = EXCLUDED.source,
  plan = EXCLUDED.plan,
  status = EXCLUDED.status,
  customer_id = EXCLUDED.customer_id,
  subscription_id = EXCLUDED.subscription_id,
  product_id = EXCLUDED.product_id,
  product_name = EXCLUDED.product_name,
  metadata = EXCLUDED.metadata,
  current_period_end = EXCLUDED.current_period_end,
  cancel_at_period_end = EXCLUDED.cancel_at_period_end
WHERE
  workspace_subscriptions.source IN ('polar', '');

-- name: UpdateSubscriptionOverrides :exec
UPDATE workspace_subscriptions
SET
  overrides = @overrides
WHERE
  workspace_id = @workspace_id;

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
      daemons d
    WHERE
      d.workspace_id = @workspace_id
  ) AS daemon_count,
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
