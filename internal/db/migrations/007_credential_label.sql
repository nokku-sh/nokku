-- Credentials: add a host-assigned label. kagi stores the passkey display
-- name here; when empty the name is derived from the credential's AAGUID and
-- transports at read time.

ALTER TABLE credentials
  ADD COLUMN IF NOT EXISTS label TEXT NOT NULL DEFAULT '';
