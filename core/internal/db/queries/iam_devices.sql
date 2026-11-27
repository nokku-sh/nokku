-- name: SeenKnownDevice :one
UPDATE known_devices
SET
  last_seen_at = @now
WHERE
  user_id = @user_id
  AND key = @key
  AND expires_at > @now
RETURNING
  id;

-- name: AddKnownDevice :one
-- An expired row of the same device is taken over.
INSERT INTO
  known_devices (user_id, key, ip, user_agent, expires_at, last_seen_at)
VALUES
  (@user_id, @key, @ip, @user_agent, @expires_at, @now)
ON CONFLICT (workspace_id, user_id, key) DO UPDATE
SET
  ip = EXCLUDED.ip,
  user_agent = EXCLUDED.user_agent,
  expires_at = EXCLUDED.expires_at,
  last_seen_at = EXCLUDED.last_seen_at
RETURNING
  *;

-- name: ListKnownDevices :many
SELECT
  *
FROM
  known_devices
WHERE
  user_id = @user_id
ORDER BY
  last_seen_at DESC;

-- name: DeleteKnownDevice :exec
DELETE FROM known_devices
WHERE
  user_id = @user_id
  AND id = @id;

-- name: DeleteExpiredKnownDevices :execrows
DELETE FROM known_devices
WHERE
  expires_at < @now;
