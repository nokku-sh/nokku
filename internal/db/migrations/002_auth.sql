-- Auth refactor: kagi-backed sessions, API keys, credentials, and one-time
-- tokens. These tables are deliberately NOT row-level-security enforced: they
-- are global lookups (a bearer token resolves before any tenant is known),
-- exactly like the existing `users` table. The backend trusts the nokku_app
-- role here; tenant isolation for these rows is structural (the tenant is
-- bound into the credential), not enforced by RLS.
--
-- Grants come from the default privileges configured in 001_base.sql.
-- Sessions: opaque, server-side, revocable tokens. token_hash is the sha256
-- of the raw token; the raw token is never persisted. subject_id is who the
-- session authorizes as; identity_id is the authenticated entity when it
-- differs (a CLI device id). tenant_id is '' for user sessions (users are
-- global) and the workspace id for machine sessions. expires_at NULL means the
-- session never expires (daemons).
CREATE TABLE IF NOT EXISTS sessions (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  token_hash BYTEA NOT NULL UNIQUE,
  tenant_id TEXT NOT NULL DEFAULT '',
  subject_id UUID NOT NULL,
  kind TEXT NOT NULL DEFAULT 'user',
  identity_id UUID,
  method TEXT NOT NULL,
  binding TEXT, -- DPoP key thumbprint (jkt)
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sessions_subject ON sessions (subject_id);

CREATE INDEX IF NOT EXISTS idx_sessions_identity ON sessions (identity_id);

-- API keys: kagi apikey records, looked up globally by key_id. secret_hash is
-- the sha256 of the secret part (computed by kagi); the secret itself is shown
-- once and never stored. subject_id is a user id (user-scoped keys) or a
-- service-account id (tenant-scoped keys); kind discriminates the two.
CREATE TABLE IF NOT EXISTS api_keys (
  key_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  subject_id UUID NOT NULL,
  kind TEXT NOT NULL DEFAULT 'user',
  secret_hash BYTEA NOT NULL,
  scopes TEXT[] NOT NULL DEFAULT '{}',
  name TEXT NOT NULL,
  expires_at TIMESTAMPTZ, -- NULL = never expires
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys (tenant_id);

CREATE INDEX IF NOT EXISTS idx_api_keys_subject ON api_keys (subject_id);

-- Credentials: kagi's credential model (one table for passwords, passkeys,
-- and external identities). tenant_id is '' for nokku (users are global). The
-- unique index on (tenant_id, type, provider, subject) makes linking external
-- identities idempotent; password credentials use an empty subject and are
-- looked up per user.
CREATE TABLE IF NOT EXISTS credentials (
  tenant_id TEXT NOT NULL DEFAULT '',
  id TEXT NOT NULL,
  user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  provider TEXT NOT NULL DEFAULT '',
  subject TEXT NOT NULL DEFAULT '',
  data BYTEA,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_credentials_subject ON credentials (tenant_id, type, provider, subject)
WHERE
  subject <> '';

CREATE INDEX IF NOT EXISTS idx_credentials_user ON credentials (user_id, type);

-- One-time tokens: email verification and password reset. token_hash is the
-- sha256 of the token; the raw token is emailed and never stored.
CREATE TABLE IF NOT EXISTS one_time_tokens (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  token_hash BYTEA NOT NULL UNIQUE,
  user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  purpose TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_one_time_tokens_user ON one_time_tokens (user_id);

-- Auto-update updated_at on credentials (001_base.sql only wires triggers for
-- tables that existed at migration time).
CREATE TRIGGER update_credentials_updated_at BEFORE
UPDATE ON credentials FOR EACH ROW EXECUTE FUNCTION update_updated_at_column ();
