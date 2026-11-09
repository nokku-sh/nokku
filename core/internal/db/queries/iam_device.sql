-- name: CreateDeviceGrant :exec
INSERT INTO
  device_grants (device_code_hash, user_code, ip, user_agent, loopback_port, expires_at)
VALUES
  (@device_code_hash, @user_code, @ip, @user_agent, sqlc.narg ('loopback_port'), @expires_at);

-- name: GetPendingDeviceGrant :one
-- For the approval page. It does not spend the code.
SELECT
  ip,
  user_agent,
  (loopback_port IS NOT NULL)::BOOLEAN AS loopback
FROM
  device_grants
WHERE
  user_code = @user_code
  AND status = 'pending'
  AND expires_at > NOW();

-- name: DecideDeviceGrant :one
-- Only a pending grant changes, so a code is decided once. Only a loopback grant keeps the code.
UPDATE device_grants
SET
  status = @status,
  user_id = @user_id,
  approved_method = @approved_method,
  loopback_code_hash = CASE
    WHEN loopback_port IS NULL THEN NULL
    ELSE sqlc.narg ('loopback_code_hash')
  END
WHERE
  user_code = @user_code
  AND status = 'pending'
  AND expires_at > NOW()
RETURNING
  loopback_port;

-- name: GetDeviceGrant :one
SELECT
  *
FROM
  device_grants
WHERE
  device_code_hash = @device_code_hash
  AND expires_at > NOW();

-- name: NoteDeviceGrantPoll :exec
UPDATE device_grants
SET
  polled_at = @polled_at,
  violations = @violations
WHERE
  device_code_hash = @device_code_hash;

-- name: ConsumeDeviceGrant :one
-- A decided grant is answered once. Two polls at the same time get one session between them.
DELETE FROM device_grants
WHERE
  device_code_hash = @device_code_hash
  AND status = @status
RETURNING
  *;

-- name: DeleteExpiredDeviceGrants :execrows
DELETE FROM device_grants
WHERE
  expires_at < @now;
