-- name: LockWebCA :one
-- The row lock keeps two servers from both issuing a new certificate.
SELECT
  private_key,
  certificate
FROM
  web_ca
WHERE
  id = 1
FOR UPDATE;

-- name: InsertWebCA :exec
INSERT INTO
  web_ca (id, private_key, certificate)
VALUES
  (1, @private_key, @certificate)
ON CONFLICT (id) DO NOTHING;

-- name: UpdateWebCACertificate :exec
UPDATE web_ca
SET
  certificate = @certificate,
  updated_at = NOW()
WHERE
  id = 1;
