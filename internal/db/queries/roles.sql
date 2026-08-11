-- name: EnsureRole :exec
INSERT INTO
  roles (name, description)
VALUES
  (@name, @description)
ON CONFLICT (name) DO NOTHING;
