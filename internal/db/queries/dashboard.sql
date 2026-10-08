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
      d.last_seen_at > @seen_after::TIMESTAMPTZ
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
  )::INTEGER AS users;

-- name: ListSoonestCAs :many
SELECT
  *
FROM
  ssh_cas
WHERE
  is_active = TRUE
  AND not_after > NOW()
ORDER BY
  not_after ASC
LIMIT
  3;

-- name: ListOpenRecordings :many
-- A crashed daemon never closes its recordings, so only trust open ones
-- behind a daemon that is still connected.
SELECT
  r.id,
  d.id AS daemon_id,
  r.username,
  r.started_at,
  d.name AS daemon_name
FROM
  recordings r
  JOIN daemons d ON d.id = r.daemon_id
WHERE
  r.ended_at IS NULL
  AND r.started_at > NOW() - INTERVAL '24 hours'
  AND d.last_seen_at > @seen_after::TIMESTAMPTZ
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
