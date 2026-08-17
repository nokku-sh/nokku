-- Daemon and service-account auth move fully onto kagi: DPoP-bound sessions
-- for daemons, API keys for service accounts. The legacy challenge-auth
-- columns and the opaque nks_ token hash are dropped.

ALTER TABLE daemons DROP COLUMN IF EXISTS auth_method;
ALTER TABLE daemons DROP COLUMN IF EXISTS auth_pubkey;

ALTER TABLE service_accounts DROP COLUMN IF EXISTS token_hash;
