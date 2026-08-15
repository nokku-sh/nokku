-- Base schema for nokku.
--
-- This file is migration 1 and captures the full schema as it existed
-- before versioned migrations were introduced (previously applied by
-- pg-schema-diff at boot). Never edit it: schema changes go in new
-- numbered migration files (002_..., 003_...).
--
-- Squashing: when the migration list grows unwieldy, dump the current
-- schema from a fully migrated database (pg_dump --schema-only --no-owner),
-- prepend the role creation block from the top of this file (pg_dump does
-- not dump roles), replace this file with the dump, and delete the old
-- migrations. The app detects databases ahead of the available migrations
-- and stamps them down automatically (see internal/db/migrate.go). Down
-- migrations across the squash boundary are gone: rollback means restoring
-- from backup.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Tables ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  name TEXT NOT NULL,
  username TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE CHECK (email = lower(email)),
  email_verified BOOLEAN NOT NULL DEFAULT FALSE,
  password_hash TEXT, -- nullable for passwordless accounts
  picture TEXT,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  enable_email_recovery BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_devices (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'cli', -- cli, web
  auth_method TEXT NOT NULL DEFAULT 'token',
  auth_pubkey TEXT, -- PEM-encoded ECDSA public key used to verify signed request challenges.
  token_hash TEXT,
  expires_at TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '6 months'),
  last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_identities (
  provider_id TEXT NOT NULL, -- identifier from the identity provider
  provider TEXT NOT NULL, -- google, github, or workspace id
  user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  provider_email TEXT, -- email from provider (can be different from user email)
  provider_username TEXT, -- username from provider
  protocol TEXT NOT NULL DEFAULT 'oauth' CHECK (protocol IN ('oauth', 'oidc', 'saml')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (provider_id, provider)
);

CREATE TABLE IF NOT EXISTS passkeys (
  id TEXT PRIMARY KEY, -- base64-encoded credential ID
  user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  name TEXT,
  public_key BYTEA NOT NULL,
  attestation_type TEXT NOT NULL, -- none, basic, self
  aaguid BYTEA, -- authenticator's unique ID
  sign_count BIGINT NOT NULL DEFAULT 0, -- protects against cloned authenticators
  transports TEXT[], -- [usb, ble, nfc, internal]
  backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
  backup_state BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS backup_codes (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  used_at TIMESTAMPTZ, -- NULL until used
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS roles (name TEXT PRIMARY KEY, description TEXT NOT NULL DEFAULT '');

CREATE TABLE IF NOT EXISTS workspaces (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  name TEXT NOT NULL,
  description TEXT,
  enroll_token_hash TEXT,
  enroll_expires_at TIMESTAMPTZ,
  invite_token_hash TEXT,
  invite_expires_at TIMESTAMPTZ,
  settings JSONB NOT NULL DEFAULT '{}',
  created_by UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS workspace_members (
  workspace_id UUID NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  role_name TEXT NOT NULL REFERENCES roles (name) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (workspace_id, user_id)
);

CREATE TABLE IF NOT EXISTS workspace_subscriptions (
  workspace_id UUID PRIMARY KEY REFERENCES workspaces (id) ON DELETE CASCADE,
  source TEXT NOT NULL DEFAULT '', -- stripe, manual, ...
  plan TEXT NOT NULL DEFAULT '', -- community, flex, enterprise
  status TEXT NOT NULL DEFAULT '',
  customer_id TEXT NOT NULL DEFAULT '', -- stripe customer id, opaque
  subscription_id TEXT NOT NULL DEFAULT '', -- stripe subscription id, opaque
  current_period_end TIMESTAMPTZ,
  cancel_at_period_end BOOLEAN NOT NULL DEFAULT FALSE,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS workspace_domains (
  domain TEXT PRIMARY KEY CHECK (domain = lower(domain)), -- e.g., "acme.com"
  workspace_id UUID NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
  verification_token TEXT DEFAULT encode(gen_random_bytes (16), 'hex') NOT NULL, -- Token for verification
  verified_at TIMESTAMPTZ, -- NULL until verified
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, domain)
);

CREATE TABLE IF NOT EXISTS oidc_providers (
  workspace_id UUID PRIMARY KEY REFERENCES workspaces (id) ON DELETE CASCADE,
  name TEXT NOT NULL DEFAULT 'OpenID Connect', -- Display name, e.g., "Okta", "Azure AD"
  issuer_url TEXT, -- e.g., "https://accounts.google.com"
  client_id TEXT,
  client_secret BYTEA, -- Encrypted via envelope encryption
  scopes TEXT[] NOT NULL DEFAULT ARRAY['openid', 'email', 'profile'],
  -- Claim mappings
  email_claim TEXT NOT NULL DEFAULT 'email',
  name_claim TEXT NOT NULL DEFAULT 'name',
  username_claim TEXT NOT NULL DEFAULT 'preferred_username',
  picture_claim TEXT NOT NULL DEFAULT 'picture',
  -- Settings
  enforce_sso BOOLEAN NOT NULL DEFAULT FALSE,
  allow_jit_provisioning BOOLEAN NOT NULL DEFAULT TRUE,
  use_pkce BOOLEAN NOT NULL DEFAULT FALSE,
  is_active BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS saml_providers (
  workspace_id UUID PRIMARY KEY REFERENCES workspaces (id) ON DELETE CASCADE,
  name TEXT NOT NULL DEFAULT 'SAML', -- Display name
  -- Identity Provider metadata URL 
  metadata_url TEXT, -- e.g., http://localhost:8080/realms/master/protocol/saml/descriptor
  -- Attribute mappings (SAML sends user data as attributes)
  email_attribute TEXT NOT NULL DEFAULT 'email',
  name_attribute TEXT NOT NULL DEFAULT 'name',
  username_attribute TEXT NOT NULL DEFAULT 'username',
  picture_attribute TEXT, -- Optional
  -- Service Provider private key (for signing requests)
  sp_private_key BYTEA, -- Encrypted via envelope encryption
  sp_certificate TEXT,
  sp_cert_expires_at TIMESTAMPTZ,
  -- Settings
  enforce_sso BOOLEAN NOT NULL DEFAULT FALSE,
  allow_jit_provisioning BOOLEAN NOT NULL DEFAULT TRUE,
  is_active BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS service_accounts (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
  name TEXT NOT NULL, -- e.g., "github-actions-deploy", "ansible-prod"
  description TEXT,
  token_hash TEXT,
  role_name TEXT NOT NULL DEFAULT 'viewer' REFERENCES roles (name),
  last_used_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ, -- Optional expiration for temporary access
  tags TEXT[] NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, name)
);

CREATE TABLE IF NOT EXISTS daemons (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  -- Signing method used for request authentication: 'tpm' or 'soft'.
  auth_method TEXT NOT NULL,
  auth_pubkey TEXT NOT NULL, -- PEM-encoded ECDSA public key 
  status INTEGER NOT NULL DEFAULT 1, -- 1=pending, 2=accepted, 3=rejected
  online BOOLEAN NOT NULL DEFAULT FALSE,
  config JSONB NOT NULL DEFAULT '{}',
  metadata JSONB NOT NULL DEFAULT '{}',
  last_used_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, name)
);

CREATE TABLE IF NOT EXISTS teams (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  tags TEXT[] NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS team_members (
  workspace_id UUID NOT NULL,
  user_id UUID NOT NULL,
  team_id UUID NOT NULL REFERENCES teams (id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (user_id, team_id),
  FOREIGN KEY (workspace_id, user_id) REFERENCES workspace_members (workspace_id, user_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS certificate_authorities (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  certificate TEXT NOT NULL, -- PEM encoded certificate
  private_key BYTEA NOT NULL, -- Encrypted private key
  public_key TEXT NOT NULL, -- OpenSSH wire format
  serial_number TEXT NOT NULL UNIQUE,
  subject TEXT NOT NULL,
  not_before TIMESTAMPTZ NOT NULL,
  not_after TIMESTAMPTZ NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  is_default BOOLEAN NOT NULL DEFAULT FALSE,
  key_type INTEGER NOT NULL DEFAULT 3, -- 1 = RSA, 2 = ECDSA, 3 = ED25519
  authority_type INTEGER NOT NULL DEFAULT 1, -- 1 = SSH, 2 = X509
  key_bits INTEGER NOT NULL,
  lifetime INTERVAL NOT NULL DEFAULT '8760 hours',
  -- User certificate config 
  user_default_ttl INTERVAL NOT NULL DEFAULT '120 hours', -- 5 days
  user_max_ttl INTERVAL NOT NULL DEFAULT '168 hours', -- 7 days
  user_extensions JSONB DEFAULT '{"permit-pty": "", "permit-user-rc": ""}',
  user_critical_options JSONB DEFAULT '{}',
  -- Host certificate config
  host_default_ttl INTERVAL NOT NULL DEFAULT '2160 hours', -- 3 months
  host_max_ttl INTERVAL NOT NULL DEFAULT '4320 hours', -- 6 months
  -- Shared config
  allowed_key_types INTEGER[] DEFAULT ARRAY[1, 2, 3],
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, name),
  CHECK (not_before < not_after),
  CHECK (authority_type IN (1, 2)),
  CHECK (user_default_ttl <= user_max_ttl),
  CHECK (host_default_ttl <= host_max_ttl)
);

CREATE TABLE IF NOT EXISTS targets (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
  ca_id UUID REFERENCES certificate_authorities (id) ON DELETE SET NULL,
  daemon_id UUID REFERENCES daemons (id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  endpoints TEXT[],
  tags TEXT[] NOT NULL DEFAULT '{}',
  metadata JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, name)
);

CREATE TABLE IF NOT EXISTS principals (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
  target_id UUID NOT NULL REFERENCES targets (id) ON DELETE CASCADE,
  username TEXT NOT NULL DEFAULT 'root', -- e.g. "root", "ubuntu", "ec2-user"
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (target_id, username)
);

CREATE TABLE IF NOT EXISTS principal_users (
  principal_id UUID NOT NULL REFERENCES principals (id) ON DELETE CASCADE,
  workspace_id UUID NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (principal_id, user_id)
);

CREATE TABLE IF NOT EXISTS principal_teams (
  principal_id UUID NOT NULL REFERENCES principals (id) ON DELETE CASCADE,
  workspace_id UUID NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
  team_id UUID NOT NULL REFERENCES teams (id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (principal_id, team_id)
);

CREATE TABLE IF NOT EXISTS principal_service_accounts (
  principal_id UUID NOT NULL REFERENCES principals (id) ON DELETE CASCADE,
  workspace_id UUID NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
  service_account_id UUID NOT NULL REFERENCES service_accounts (id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (principal_id, service_account_id)
);

CREATE TABLE IF NOT EXISTS recordings (
  id UUID PRIMARY KEY DEFAULT uuidv7(), -- the session id
  workspace_id UUID NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
  daemon_id UUID NOT NULL REFERENCES daemons (id) ON DELETE CASCADE,
  username TEXT NOT NULL,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ended_at TIMESTAMPTZ,
  size_bytes BIGINT NOT NULL DEFAULT 0,
  key_fingerprint TEXT NOT NULL DEFAULT '',
  -- False when the upload stream ended without a final message (e.g. the
  -- daemon died mid-session): the recording is truncated.
  complete BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Keysets (for envelope encryption - singleton)
CREATE TABLE IF NOT EXISTS keysets (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  data BYTEA NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes --------------------------------------------------------------------
CREATE INDEX idx_user_identities_user_id ON user_identities (user_id);

CREATE INDEX idx_user_identities_provider_email ON user_identities (provider_email);

CREATE INDEX idx_user_devices_user_id ON user_devices (user_id);

CREATE INDEX idx_passkeys_user_id ON passkeys (user_id);

CREATE INDEX idx_backup_codes_user_id ON backup_codes (user_id);

CREATE INDEX idx_workspaces_created_by ON workspaces (created_by);

CREATE INDEX idx_workspace_members_user_id ON workspace_members (user_id, workspace_id);

CREATE INDEX idx_service_accounts_workspace_id ON service_accounts (workspace_id);

CREATE INDEX idx_service_accounts_name_trgm ON service_accounts USING GIN (name gin_trgm_ops);

CREATE INDEX idx_service_accounts_description_trgm ON service_accounts USING GIN (description gin_trgm_ops);

CREATE INDEX idx_service_accounts_tags ON service_accounts USING GIN (tags);

CREATE INDEX idx_daemons_workspace_id ON daemons (workspace_id);

CREATE INDEX idx_daemons_name_trgm ON daemons USING GIN (name gin_trgm_ops);

CREATE INDEX idx_teams_workspace_id ON teams (workspace_id);

CREATE INDEX idx_teams_name_trgm ON teams USING GIN (name gin_trgm_ops);

CREATE INDEX idx_teams_description_trgm ON teams USING GIN (description gin_trgm_ops);

CREATE INDEX idx_teams_tags ON teams USING GIN (tags);

CREATE INDEX idx_team_members_team_id ON team_members (team_id);

CREATE INDEX idx_ca_workspace_id ON certificate_authorities (workspace_id);

CREATE INDEX idx_ca_name_trgm ON certificate_authorities USING GIN (name gin_trgm_ops);

CREATE UNIQUE INDEX idx_ca_default_per_workspace ON certificate_authorities (workspace_id)
WHERE
  is_default = TRUE;

CREATE INDEX idx_targets_workspace_id ON targets (workspace_id);

CREATE INDEX idx_targets_ca_id ON targets (ca_id);

CREATE INDEX idx_targets_daemon_id ON targets (daemon_id);

CREATE INDEX idx_targets_tags ON targets USING GIN (tags);

CREATE INDEX idx_targets_name_trgm ON targets USING GIN (name gin_trgm_ops);

CREATE INDEX idx_targets_description_trgm ON targets USING GIN (description gin_trgm_ops);

CREATE INDEX idx_principals_workspace_id ON principals (workspace_id);

CREATE INDEX idx_principals_target_id ON principals (target_id);

CREATE INDEX idx_principal_users_user_id ON principal_users (user_id);

CREATE INDEX idx_principal_users_workspace_id ON principal_users (workspace_id);

CREATE INDEX idx_principal_teams_team_id ON principal_teams (team_id);

CREATE INDEX idx_principal_teams_workspace_id ON principal_teams (workspace_id);

CREATE INDEX idx_principal_sa_service_account_id ON principal_service_accounts (service_account_id);

CREATE INDEX idx_principal_sa_workspace_id ON principal_service_accounts (workspace_id);

CREATE INDEX idx_users_name_trgm ON users USING GIN (name gin_trgm_ops);

CREATE INDEX idx_users_username_trgm ON users USING GIN (username gin_trgm_ops);

CREATE INDEX idx_users_email_trgm ON users USING GIN (email gin_trgm_ops);

CREATE INDEX recordings_workspace_started_idx ON recordings (workspace_id, started_at DESC);

-- Functions ------------------------------------------------------------------
CREATE OR REPLACE FUNCTION current_workspace_id () RETURNS UUID AS $$
  SELECT NULLIF(current_setting('nokku.workspace_id', TRUE), '')::UUID
$$ LANGUAGE sql STABLE;

CREATE OR REPLACE FUNCTION current_actor_id () RETURNS UUID AS $$
  SELECT NULLIF(current_setting('nokku.actor_id', TRUE), '')::UUID
$$ LANGUAGE sql STABLE;

-- Triggers -------------------------------------------------------------------
-- Ensure only one default CA per workspace
CREATE OR REPLACE FUNCTION enforce_single_default_ca () RETURNS TRIGGER AS $$
BEGIN
  IF NEW.is_default = TRUE THEN
    UPDATE certificate_authorities
    SET is_default = FALSE
    WHERE workspace_id = NEW.workspace_id
      AND id != NEW.id
      AND is_default = TRUE;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_single_default_ca BEFORE INSERT
OR
UPDATE OF is_default ON certificate_authorities FOR EACH ROW WHEN (NEW.is_default = TRUE)
EXECUTE FUNCTION enforce_single_default_ca ();

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column () RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Automatically create triggers for all tables with updated_at column
DO $$
DECLARE
  t RECORD;
  trigger_name TEXT;
BEGIN
  FOR t IN
    SELECT table_name
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND column_name = 'updated_at'
  LOOP
    trigger_name := 'update_' || t.table_name || '_updated_at';

    EXECUTE format(
      'CREATE OR REPLACE TRIGGER %I BEFORE UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()',
      trigger_name,
      t.table_name
    );
  END LOOP;
END;
$$;

-- Roles and grants -----------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nokku_app') THEN
	 CREATE ROLE nokku_app NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nokku_system') THEN
	 CREATE ROLE nokku_system NOLOGIN BYPASSRLS;
  END IF;
END $$;

-- nokku_system bypasses RLS for internal operations
GRANT nokku_system TO nokku_app;

-- Schema permissions
GRANT USAGE ON SCHEMA public TO nokku_app,
nokku_system;

-- Table grants for nokku_app and nokku_system
GRANT
SELECT
,
  INSERT,
UPDATE,
DELETE ON ALL TABLES IN SCHEMA public TO nokku_app,
nokku_system;

GRANT USAGE,
SELECT
  ON ALL SEQUENCES IN SCHEMA public TO nokku_app,
  nokku_system;

-- Default privileges for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public
GRANT
SELECT
,
  INSERT,
UPDATE,
DELETE ON TABLES TO nokku_app,
nokku_system;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
GRANT USAGE,
SELECT
  ON SEQUENCES TO nokku_app,
  nokku_system;

-- Row-level security ---------------------------------------------------------
-- RLS enforces tenant isolation only. Every workspace-scoped table carries
-- one uniform policy: rows are visible and writable only when the request
-- pinned that workspace in the session GUC "nokku.workspace_id". The GUC is
-- set per transaction by the backend (see internal/db/connection.go).
--
-- Fail-closed properties:
--   - The application connects as nokku_app, which does not own the tables,
--     so RLS applies to every query; FORCE ROW LEVEL SECURITY extends this
--     to the table owner as well.
--   - An unset GUC makes current_workspace_id() return NULL, and
--     "workspace_id = NULL" matches nothing, so tenant tables are empty by
--     default.
--   - Truly cross-tenant operations (bootstrap, billing webhooks, background
--     jobs, pre-auth lookups) run through the nokku_system role which has
--     BYPASSRLS; that role switch is explicit in code (Connection.WithTx).
--
-- Adding a new tenant table requires exactly:
--   ALTER TABLE <t> ENABLE ROW LEVEL SECURITY;
--   ALTER TABLE <t> FORCE ROW LEVEL SECURITY;
--   CREATE POLICY tenant_isolation ON <t> FOR ALL TO nokku_app
--     USING (workspace_id = current_workspace_id())
--     WITH CHECK (workspace_id = current_workspace_id());
-- (plus one of the variants below when the table needs cross-tenant reads or
-- referential integrity checks). 
ALTER TABLE workspaces ENABLE ROW LEVEL SECURITY;

ALTER TABLE workspaces FORCE ROW LEVEL SECURITY;

ALTER TABLE workspace_members ENABLE ROW LEVEL SECURITY;

ALTER TABLE workspace_members FORCE ROW LEVEL SECURITY;

ALTER TABLE workspace_domains ENABLE ROW LEVEL SECURITY;

ALTER TABLE workspace_domains FORCE ROW LEVEL SECURITY;

ALTER TABLE workspace_subscriptions ENABLE ROW LEVEL SECURITY;

ALTER TABLE workspace_subscriptions FORCE ROW LEVEL SECURITY;

ALTER TABLE oidc_providers ENABLE ROW LEVEL SECURITY;

ALTER TABLE oidc_providers FORCE ROW LEVEL SECURITY;

ALTER TABLE saml_providers ENABLE ROW LEVEL SECURITY;

ALTER TABLE saml_providers FORCE ROW LEVEL SECURITY;

ALTER TABLE service_accounts ENABLE ROW LEVEL SECURITY;

ALTER TABLE service_accounts FORCE ROW LEVEL SECURITY;

ALTER TABLE daemons ENABLE ROW LEVEL SECURITY;

ALTER TABLE daemons FORCE ROW LEVEL SECURITY;

ALTER TABLE teams ENABLE ROW LEVEL SECURITY;

ALTER TABLE teams FORCE ROW LEVEL SECURITY;

ALTER TABLE team_members ENABLE ROW LEVEL SECURITY;

ALTER TABLE team_members FORCE ROW LEVEL SECURITY;

ALTER TABLE certificate_authorities ENABLE ROW LEVEL SECURITY;

ALTER TABLE certificate_authorities FORCE ROW LEVEL SECURITY;

ALTER TABLE targets ENABLE ROW LEVEL SECURITY;

ALTER TABLE targets FORCE ROW LEVEL SECURITY;

ALTER TABLE principals ENABLE ROW LEVEL SECURITY;

ALTER TABLE principals FORCE ROW LEVEL SECURITY;

ALTER TABLE principal_users ENABLE ROW LEVEL SECURITY;

ALTER TABLE principal_users FORCE ROW LEVEL SECURITY;

ALTER TABLE principal_teams ENABLE ROW LEVEL SECURITY;

ALTER TABLE principal_teams FORCE ROW LEVEL SECURITY;

ALTER TABLE principal_service_accounts ENABLE ROW LEVEL SECURITY;

ALTER TABLE principal_service_accounts FORCE ROW LEVEL SECURITY;

ALTER TABLE recordings ENABLE ROW LEVEL SECURITY;

ALTER TABLE recordings FORCE ROW LEVEL SECURITY;

-- Session helpers ------------------------------------------------------------
-- Membership of the current actor in a workspace. Used for cross-tenant
-- reads users legitimately need outside a pinned workspace.
CREATE OR REPLACE FUNCTION is_workspace_member (ws_id UUID) RETURNS BOOLEAN AS $$
  SELECT EXISTS (
    SELECT 1
    FROM workspace_members wm
    WHERE wm.workspace_id = ws_id
      AND wm.user_id = current_actor_id ()
  )
$$ LANGUAGE sql STABLE;

-- Workspaces -----------------------------------------------------------------
CREATE POLICY workspaces_select ON workspaces FOR
SELECT
  TO nokku_app USING (
    id = current_workspace_id ()
    OR is_workspace_member (id)
  );

CREATE POLICY workspaces_write ON workspaces FOR ALL TO nokku_app USING (id = current_workspace_id ())
WITH
  CHECK (id = current_workspace_id ());

-- Workspace members ----------------------------------------------------------
CREATE POLICY workspace_members_select ON workspace_members FOR
SELECT
  TO nokku_app USING (
    workspace_id = current_workspace_id ()
    OR user_id = current_actor_id ()
  );

CREATE POLICY workspace_members_write ON workspace_members FOR ALL TO nokku_app USING (workspace_id = current_workspace_id ())
WITH
  CHECK (workspace_id = current_workspace_id ());

-- Pure tenant tables ---------------------------------------------------------
CREATE POLICY tenant_isolation ON workspace_domains FOR ALL TO nokku_app USING (workspace_id = current_workspace_id ())
WITH
  CHECK (workspace_id = current_workspace_id ());

CREATE POLICY tenant_isolation ON workspace_subscriptions FOR ALL TO nokku_app USING (workspace_id = current_workspace_id ())
WITH
  CHECK (workspace_id = current_workspace_id ());

CREATE POLICY tenant_isolation ON oidc_providers FOR ALL TO nokku_app USING (workspace_id = current_workspace_id ())
WITH
  CHECK (workspace_id = current_workspace_id ());

CREATE POLICY tenant_isolation ON saml_providers FOR ALL TO nokku_app USING (workspace_id = current_workspace_id ())
WITH
  CHECK (workspace_id = current_workspace_id ());

CREATE POLICY tenant_isolation ON service_accounts FOR ALL TO nokku_app USING (workspace_id = current_workspace_id ())
WITH
  CHECK (workspace_id = current_workspace_id ());

CREATE POLICY tenant_isolation ON daemons FOR ALL TO nokku_app USING (workspace_id = current_workspace_id ())
WITH
  CHECK (workspace_id = current_workspace_id ());

CREATE POLICY tenant_isolation ON teams FOR ALL TO nokku_app USING (workspace_id = current_workspace_id ())
WITH
  CHECK (workspace_id = current_workspace_id ());

CREATE POLICY tenant_isolation ON certificate_authorities FOR ALL TO nokku_app USING (workspace_id = current_workspace_id ())
WITH
  CHECK (workspace_id = current_workspace_id ());

CREATE POLICY tenant_isolation ON targets FOR ALL TO nokku_app USING (workspace_id = current_workspace_id ())
WITH
  CHECK (workspace_id = current_workspace_id ());

CREATE POLICY tenant_isolation ON principals FOR ALL TO nokku_app USING (workspace_id = current_workspace_id ())
WITH
  CHECK (workspace_id = current_workspace_id ());

CREATE POLICY tenant_isolation ON recordings FOR ALL TO nokku_app USING (workspace_id = current_workspace_id ())
WITH
  CHECK (workspace_id = current_workspace_id ());

-- Junction tables ------------------------------------------------------------
CREATE POLICY team_members_isolation ON team_members FOR ALL TO nokku_app USING (workspace_id = current_workspace_id ())
WITH
  CHECK (
    workspace_id = current_workspace_id ()
    AND EXISTS (
      SELECT
        1
      FROM
        teams t
      WHERE
        t.id = team_id
        AND t.workspace_id = team_members.workspace_id
    )
  );

CREATE POLICY principal_users_isolation ON principal_users FOR ALL TO nokku_app USING (workspace_id = current_workspace_id ())
WITH
  CHECK (
    workspace_id = current_workspace_id ()
    AND EXISTS (
      SELECT
        1
      FROM
        principals p
      WHERE
        p.id = principal_id
        AND p.workspace_id = principal_users.workspace_id
    )
  );

CREATE POLICY principal_teams_isolation ON principal_teams FOR ALL TO nokku_app USING (workspace_id = current_workspace_id ())
WITH
  CHECK (
    workspace_id = current_workspace_id ()
    AND EXISTS (
      SELECT
        1
      FROM
        principals p
      WHERE
        p.id = principal_id
        AND p.workspace_id = principal_teams.workspace_id
    )
  );

CREATE POLICY principal_service_accounts_isolation ON principal_service_accounts FOR ALL TO nokku_app USING (workspace_id = current_workspace_id ())
WITH
  CHECK (
    workspace_id = current_workspace_id ()
    AND EXISTS (
      SELECT
        1
      FROM
        principals p
      WHERE
        p.id = principal_id
        AND p.workspace_id = principal_service_accounts.workspace_id
    )
  );

-- Audit schema ---------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS audit;

CREATE TABLE IF NOT EXISTS audit.audit_logs (
  id UUID NOT NULL DEFAULT uuidv7(),
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  workspace_id UUID REFERENCES public.workspaces (id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  actor_id UUID NOT NULL,
  actor_type TEXT NOT NULL,
  actor_email TEXT,
  ip_address TEXT,
  user_agent TEXT,
  status_code TEXT,
  PRIMARY KEY (timestamp, id)
)
PARTITION BY
  RANGE (timestamp);

CREATE INDEX IF NOT EXISTS idx_audit_logs_workspace_time ON audit.audit_logs (workspace_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit.audit_logs (actor_id, timestamp DESC);

-- Access for the application roles
GRANT USAGE ON SCHEMA audit TO nokku_app,
nokku_system;

GRANT
SELECT
,
  INSERT ON ALL TABLES IN SCHEMA audit TO nokku_app;

GRANT
SELECT
,
  INSERT,
  DELETE ON ALL TABLES IN SCHEMA audit TO nokku_system;

-- Partitions created later by the retention job inherit these.
ALTER DEFAULT PRIVILEGES IN SCHEMA audit
GRANT
SELECT
,
  INSERT ON TABLES TO nokku_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA audit
GRANT
SELECT
,
  INSERT,
  DELETE ON TABLES TO nokku_system;

ALTER TABLE audit.audit_logs ENABLE ROW LEVEL SECURITY;

ALTER TABLE audit.audit_logs FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname = 'audit'
      AND tablename = 'audit_logs'
      AND policyname = 'audit_logs_select'
  ) THEN
    CREATE POLICY audit_logs_select ON audit.audit_logs FOR
    SELECT
      TO nokku_app USING (workspace_id = current_workspace_id ());
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname = 'audit'
      AND tablename = 'audit_logs'
      AND policyname = 'audit_logs_insert'
  ) THEN
    CREATE POLICY audit_logs_insert ON audit.audit_logs FOR INSERT TO nokku_app
    WITH
      CHECK (TRUE);
  END IF;
END $$;
