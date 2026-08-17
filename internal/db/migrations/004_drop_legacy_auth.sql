-- Drop the legacy authentication tables and columns replaced by kagi's
-- credentials, sessions, and API keys.

ALTER TABLE users DROP COLUMN IF EXISTS password_hash;

DROP TABLE IF EXISTS user_identities;

DROP TABLE IF EXISTS passkeys;

DROP TABLE IF EXISTS user_devices;

ALTER TABLE saml_providers DROP COLUMN IF EXISTS sp_private_key;

ALTER TABLE saml_providers DROP COLUMN IF EXISTS sp_certificate;

ALTER TABLE saml_providers DROP COLUMN IF EXISTS sp_cert_expires_at;
