-- name: CreateLegalHold :one
INSERT INTO
  legal_holds (reason, starts_at, ends_at, created_by)
VALUES
  (
    @reason,
    @starts_at,
    sqlc.narg('ends_at'),
    sqlc.narg('created_by')
  )
RETURNING
  *;

-- name: ListLegalHolds :many
SELECT
  *
FROM
  legal_holds
ORDER BY
  starts_at DESC;

-- name: DeleteLegalHold :one
DELETE FROM legal_holds
WHERE
  id = @id
RETURNING
  *;

-- name: CountLegalHolds :one
SELECT
  COUNT(*)::INTEGER
FROM
  legal_holds;
