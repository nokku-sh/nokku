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

-- name: ListAccessReport :many
SELECT
  e.subject_kind::TEXT AS kind,
  e.subject_id::UUID AS subject_id,
  COALESCE(u.name, sa.name)::TEXT AS name,
  COALESCE(u.email, '')::TEXT AS email,
  e.user_ok::BOOLEAN AS active,
  COALESCE(tm.name, '')::TEXT AS via,
  t.name AS target,
  e.username,
  e.granted_at::TIMESTAMPTZ AS granted_at,
  e.expires_at,
  au.last_cert_at,
  (e.user_ok AND e.daemon_ok)::BOOLEAN AS enforced,
  (COALESCE(au.last_cert_at, e.granted_at) < NOW() - INTERVAL '90 days')::BOOLEAN AS stale
FROM
  effective_access e
  JOIN targets t ON t.id = e.target_id
  LEFT JOIN users u ON e.subject_kind = 'user'
  AND u.id = e.subject_id
  LEFT JOIN service_accounts sa ON e.subject_kind = 'service_account'
  AND sa.id = e.subject_id
  LEFT JOIN teams tm ON tm.id = e.team_id
  LEFT JOIN access_usage au ON au.target_id = t.id
  AND au.subject_id = e.subject_id
ORDER BY
  COALESCE(u.name, sa.name),
  t.name,
  e.username,
  COALESCE(tm.name, '');
