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
          AND last_seen_at > @seen_after::TIMESTAMPTZ
      ))::INTEGER AS online
    FROM
      daemons
  ) AS d;

-- name: ListPendingDaemons :many
-- The id is a uuidv7, so this is newest first.
SELECT
  *
FROM
  daemons
WHERE
  status = 1 -- pending
ORDER BY
  id DESC
LIMIT
  5;

-- name: ListOfflineDaemons :many
SELECT
  *
FROM
  daemons
WHERE
  status = 2 -- accepted
  AND COALESCE(last_seen_at <= @seen_after::TIMESTAMPTZ, TRUE)
ORDER BY
  id ASC
LIMIT
  5;

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
-- A crashed daemon never closes its recordings, so only trust open ones behind a connected daemon.
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
