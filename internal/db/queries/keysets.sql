-- name: GetKeysetData :one
SELECT
  data
FROM
  keysets
WHERE
  id = 1;

-- name: InsertKeyset :execrows
INSERT INTO
  keysets (id, data)
VALUES
  (1, @data)
ON CONFLICT (id) DO NOTHING;

-- name: LockKeyset :one
-- The row lock keeps two rotations from running at once.
SELECT
  data,
  rotated_at
FROM
  keysets
WHERE
  id = 1
FOR UPDATE;

-- name: UpdateKeyset :exec
UPDATE keysets
SET
  data = @data,
  rotated_at = @rotated_at,
  updated_at = NOW()
WHERE
  id = 1;
