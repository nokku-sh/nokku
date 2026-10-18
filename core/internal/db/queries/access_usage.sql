-- name: TouchAccessUsage :exec
INSERT INTO
  access_usage (target_id, subject_id)
VALUES
  (@target_id, @subject_id)
ON CONFLICT (target_id, subject_id) DO UPDATE
SET
  last_cert_at = NOW()
WHERE
  -- The review counts in days. Not rewriting the row on every certificate saves a write per login.
  access_usage.last_cert_at < NOW() - INTERVAL '1 hour';

-- name: TouchAccessUsageByDaemon :exec
INSERT INTO
  access_usage (target_id, subject_id)
SELECT
  t.id,
  @subject_id
FROM
  targets t
WHERE
  t.daemon_id = @daemon_id
ON CONFLICT (target_id, subject_id) DO UPDATE
SET
  last_cert_at = NOW()
WHERE
  -- The review counts in days. Not rewriting the row on every certificate saves a write per login.
  access_usage.last_cert_at < NOW() - INTERVAL '1 hour';

-- name: ListAccessReport :many
-- One row per subject, account and the way the subject holds it. Team grants are expanded to the members. A row is
-- stale when nobody got a certificate for the target in 90 days, counted from the grant when there never was one.
WITH
  holders AS (
    SELECT
      g.account_id,
      'user' AS kind,
      u.id AS subject_id,
      u.name,
      u.email,
      u.active,
      '' AS via,
      g.created_at AS granted_at,
      g.expires_at
    FROM
      live_grants g
      JOIN users u ON u.id = g.user_id
    UNION ALL
    SELECT
      g.account_id,
      'user',
      u.id,
      u.name,
      u.email,
      u.active,
      tm.name,
      g.created_at,
      g.expires_at
    FROM
      live_grants g
      JOIN teams tm ON tm.id = g.team_id
      JOIN team_members m ON m.team_id = tm.id
      JOIN users u ON u.id = m.user_id
    UNION ALL
    SELECT
      g.account_id,
      'service_account',
      sa.id,
      sa.name,
      '',
      TRUE,
      '',
      g.created_at,
      g.expires_at
    FROM
      live_grants g
      JOIN service_accounts sa ON sa.id = g.service_account_id
  )
SELECT
  h.kind::TEXT AS kind,
  h.subject_id::UUID AS subject_id,
  h.name::TEXT AS name,
  h.email::TEXT AS email,
  h.active::BOOLEAN AS active,
  h.via::TEXT AS via,
  t.name AS target,
  p.username,
  h.granted_at::TIMESTAMPTZ AS granted_at,
  h.expires_at,
  u.last_cert_at,
  (COALESCE(u.last_cert_at, h.granted_at) < NOW() - INTERVAL '90 days')::BOOLEAN AS stale
FROM
  holders h
  JOIN target_accounts p ON p.id = h.account_id
  JOIN targets t ON t.id = p.target_id
  LEFT JOIN access_usage u ON u.target_id = t.id
  AND u.subject_id = h.subject_id
ORDER BY
  h.name,
  t.name,
  p.username,
  h.via;
