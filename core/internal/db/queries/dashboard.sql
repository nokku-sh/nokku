-- name: DashboardCounts :one
SELECT
  (
    SELECT
      COUNT(*)
    FROM
      targets t
  )::INTEGER AS targets,
  (
    SELECT
      COUNT(*)
    FROM
      targets t
      JOIN daemons d ON d.workspace_id = t.workspace_id
      AND d.id = t.daemon_id
    WHERE
      COALESCE(d.id = ANY (@connected::UUID[]), FALSE)
  )::INTEGER AS targets_online,
  (
    SELECT
      COUNT(*)
    FROM
      targets t
    WHERE
      t.daemon_id IS NULL
  )::INTEGER AS targets_manual,
  (
    SELECT
      COUNT(*)
    FROM
      users u
    WHERE
      u.active
  )::INTEGER AS users,
  d.total AS daemons,
  d.online AS daemons_online
FROM
  (
    SELECT
      COUNT(*)::INTEGER AS total,
      (COUNT(*) FILTER (
        WHERE
          status <> 1 -- pending
          AND COALESCE(id = ANY (@connected::UUID[]), FALSE)
      ))::INTEGER AS online
    FROM
      daemons
  ) AS d;

-- name: ListPendingDaemons :many
-- The id is a uuidv7, so this is newest first.
SELECT
  sqlc.embed(d),
  t.name
FROM
  daemons d
  JOIN targets t ON t.daemon_id = d.id
WHERE
  d.status = 1 -- pending
ORDER BY
  d.id DESC
LIMIT
  5;

-- name: ListOfflineTargets :many
SELECT
  sqlc.embed(t)
FROM
  daemons d
  JOIN targets t ON t.daemon_id = d.id
WHERE
  d.status = 2 -- accepted
  AND NOT COALESCE(d.id = ANY (@connected::UUID[]), FALSE)
ORDER BY
  d.id ASC
LIMIT
  5;

-- name: ListOpenRecordings :many
-- A crashed daemon never closes its recordings, so only trust open ones behind a connected daemon.
SELECT
  r.id,
  d.id AS daemon_id,
  r.username,
  r.started_at,
  t.name AS daemon_name
FROM
  recordings r
  JOIN daemons d ON d.id = r.daemon_id
  JOIN targets t ON t.daemon_id = d.id
WHERE
  r.ended_at IS NULL
  AND r.started_at > NOW() - INTERVAL '24 hours'
  AND COALESCE(d.id = ANY (@connected::UUID[]), FALSE)
ORDER BY
  r.started_at DESC
LIMIT
  20;

-- name: AuditActivityByHour :many
SELECT
  date_trunc('hour', timestamp)::TIMESTAMPTZ AS hour,
  COUNT(*)::INTEGER AS events,
  (COUNT(*) FILTER (
    WHERE
      NOT ok
  ))::INTEGER AS failures
FROM
  audit.audit_logs
WHERE
  timestamp >= @since::TIMESTAMPTZ
GROUP BY
  1
ORDER BY
  1;

-- name: ListEndingGrants :many
-- Grants given in one go share their end, so they come back as one row with its first 20 servers.
SELECT
  g.subject_kind::TEXT AS subject_kind,
  g.subject_id,
  COALESCE(NULLIF(u.name, ''), u.email, m.name, s.name, '')::TEXT AS subject_name,
  p.username,
  g.expires_at::TIMESTAMPTZ AS expires_at,
  (array_agg(t.id ORDER BY t.name))[1:20]::UUID[] AS target_ids,
  (array_agg(t.name ORDER BY t.name))[1:20]::TEXT[] AS target_names,
  COUNT(*)::INTEGER AS target_count,
  (COUNT(*) OVER ())::INTEGER AS total
FROM
  live_grants g
  JOIN target_accounts p ON p.id = g.account_id
  JOIN targets t ON t.id = p.target_id
  LEFT JOIN users u ON u.id = g.user_id
  LEFT JOIN teams m ON m.id = g.team_id
  LEFT JOIN service_accounts s ON s.id = g.service_account_id
WHERE
  g.expires_at <= NOW() + INTERVAL '24 hours'
  AND COALESCE(u.active, TRUE)
GROUP BY
  g.subject_kind,
  g.subject_id,
  subject_name,
  p.username,
  g.expires_at
ORDER BY
  g.expires_at,
  subject_name
LIMIT
  5;
