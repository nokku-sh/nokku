-- name: UpsertRole :exec
INSERT INTO
  roles (name, description, permissions)
VALUES
  (@name, @description, @permissions)
ON CONFLICT (name) DO UPDATE
SET
  description = EXCLUDED.description,
  permissions = EXCLUDED.permissions;
