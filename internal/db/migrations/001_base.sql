-- Base schema for nokku.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  email TEXT NOT NULL UNIQUE CHECK (email = lower(email)),
  name TEXT NOT NULL DEFAULT '',
  picture TEXT,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  email_verified BOOLEAN NOT NULL DEFAULT FALSE,
  disable_password_reset BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS credentials (
  id TEXT PRIMARY KEY, -- method-specific id: webauthn credential id or uuidv7
  user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  type TEXT NOT NULL, -- password, passkey, oauth2, oidc, saml, backup_code
  provider TEXT NOT NULL DEFAULT '', -- github, google, or the sso provider id
  subject TEXT NOT NULL DEFAULT '', -- external identity subject or code hash
  data BYTEA NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  last_used_at TIMESTAMPTZ, -- last successful sign-in with it
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS one_time_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  purpose TEXT NOT NULL, -- verify_email, password_reset
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS workspaces (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  name TEXT NOT NULL,
  description TEXT,
  settings JSONB NOT NULL DEFAULT '{}',
  -- The single owner. RESTRICT: deleting a user never takes a workspace down,
  -- ownership moves first or the workspace is deleted explicitly.
  created_by UUID NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Bumped by triggers whenever what a daemon enforces changes. No RLS: it
-- holds a counter, not tenant data, and only the SECURITY DEFINER trigger
-- functions below may write it.
CREATE TABLE IF NOT EXISTS workspace_state (
  workspace_id UUID PRIMARY KEY REFERENCES workspaces (id) ON DELETE CASCADE,
  version BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS workspace_members (
  workspace_id UUID NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  role_name TEXT NOT NULL CHECK (role_name IN ('member', 'viewer', 'editor', 'admin', 'owner')),
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

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT NOT NULL PRIMARY KEY,
  subject_id TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'user', -- user, cli, web_device, daemon
  method TEXT NOT NULL, -- password, passkey, oidc, oauth2, saml, backup_code, device
  workspace_id UUID REFERENCES workspaces (id) ON DELETE CASCADE, -- tenant pin for daemons; NULL for global users
  binding TEXT NOT NULL DEFAULT '', -- DPoP JWK thumbprint, empty for cookie sessions
  label TEXT NOT NULL DEFAULT '', -- display name for "your devices" listings
  ip TEXT NOT NULL DEFAULT '', -- of the request that created the session
  user_agent TEXT NOT NULL DEFAULT '', -- of the request that created the session
  expires_at TIMESTAMPTZ, -- NULL = non-expiring (daemons re-auth via DPoP proofs)
  last_seen_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sso_providers (
  workspace_id UUID REFERENCES workspaces (id) ON DELETE CASCADE,
  provider_id TEXT NOT NULL PRIMARY KEY,
  method TEXT NOT NULL, -- oidc, oauth2, saml
  name TEXT NOT NULL DEFAULT '',
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  config BYTEA NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scim_tokens (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS workspace_domains (
  workspace_id UUID NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
  domain TEXT CHECK (domain = lower(domain)),
  token TEXT NOT NULL DEFAULT encode(gen_random_bytes (16), 'hex'), -- DNS TXT verification token
  verified_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (workspace_id, domain)
);

CREATE TABLE IF NOT EXISTS service_accounts (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
  name TEXT NOT NULL, -- e.g., "github-actions-deploy", "ansible-prod"
  description TEXT,
  token_hash TEXT, -- bearer credential for the service account (HashedToken)
  role_name TEXT NOT NULL DEFAULT 'member' CHECK (role_name IN ('member', 'viewer', 'editor', 'admin', 'owner')),
  last_used_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ, -- Optional expiration for temporary access
  tags TEXT[] NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, name),
  UNIQUE (workspace_id, id)
);

CREATE TABLE IF NOT EXISTS daemons (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  status INTEGER NOT NULL DEFAULT 1, -- 1=pending, 2=accepted, 3=rejected
  -- Refreshed by the core instance holding the control stream. Online means
  -- seen within the last 30 seconds, so a crashed instance needs no cleanup.
  last_seen_at TIMESTAMPTZ,
  key_thumbprint TEXT,
  config JSONB NOT NULL DEFAULT '{}',
  metadata JSONB NOT NULL DEFAULT '{}',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, name),
  UNIQUE (workspace_id, id),
  -- The DPoP key is the machine's identity. Re-enrolling reuses the row.
  UNIQUE (workspace_id, key_thumbprint)
);

CREATE TABLE IF NOT EXISTS teams (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  tags TEXT[] NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, id)
);

CREATE TABLE IF NOT EXISTS team_members (
  workspace_id UUID NOT NULL,
  user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  team_id UUID NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (user_id, team_id),
  FOREIGN KEY (workspace_id, user_id) REFERENCES workspace_members (workspace_id, user_id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, team_id) REFERENCES teams (workspace_id, id) ON DELETE CASCADE
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
  user_extensions JSONB DEFAULT '{"permit-pty": "", "permit-user-rc": "", "permit-port-forwarding": "", "permit-agent-forwarding": ""}',
  user_critical_options JSONB DEFAULT '{}',
  -- Host certificate config
  host_default_ttl INTERVAL NOT NULL DEFAULT '168 hours', -- 7 days
  host_max_ttl INTERVAL NOT NULL DEFAULT '720 hours', -- 30 days
  -- Shared config
  allowed_key_types INTEGER[] DEFAULT ARRAY[1, 2, 3],
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, name),
  UNIQUE (workspace_id, id),
  CHECK (not_before < not_after),
  CHECK (authority_type IN (1, 2)),
  CHECK (user_default_ttl <= user_max_ttl),
  CHECK (host_default_ttl <= host_max_ttl)
);

CREATE TABLE IF NOT EXISTS targets (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
  ca_id UUID,
  daemon_id UUID,
  name TEXT NOT NULL,
  description TEXT,
  endpoints TEXT[],
  host_public_key TEXT,
  tags TEXT[] NOT NULL DEFAULT '{}',
  metadata JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, name),
  UNIQUE (workspace_id, id),
  FOREIGN KEY (workspace_id, ca_id) REFERENCES certificate_authorities (workspace_id, id) ON DELETE SET NULL (ca_id),
  FOREIGN KEY (workspace_id, daemon_id) REFERENCES daemons (workspace_id, id) ON DELETE CASCADE
);

-- Join tokens. Enroll tokens bring daemons in, invite tokens bring people
-- in. The plaintext is "<id>_<secret>", so redemption looks the row up by id
-- and compares the hash of the whole token.
CREATE TABLE IF NOT EXISTS workspace_tokens (
  id UUID PRIMARY KEY,
  workspace_id UUID NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
  kind INTEGER NOT NULL CHECK (kind IN (1, 2)), -- 1=enroll, 2=invite
  label TEXT NOT NULL DEFAULT '',
  token_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ, -- NULL never expires
  max_uses INTEGER CHECK (max_uses > 0), -- NULL is unlimited
  uses INTEGER NOT NULL DEFAULT 0,
  auto_approve BOOLEAN NOT NULL DEFAULT FALSE, -- enroll only
  ca_id UUID, -- enroll only, NULL is the workspace default
  role_name TEXT CHECK (role_name IN ('member', 'viewer', 'editor', 'admin', 'owner')), -- invite only
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at TIMESTAMPTZ,
  FOREIGN KEY (workspace_id, ca_id) REFERENCES certificate_authorities (workspace_id, id) ON DELETE SET NULL (ca_id),
  CHECK (
    kind = 1
    OR (
      NOT auto_approve
      AND ca_id IS NULL
    )
  ),
  CHECK ((kind = 2) = (role_name IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS principals (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
  target_id UUID NOT NULL,
  username TEXT NOT NULL DEFAULT 'root', -- e.g. "root", "ubuntu", "ec2-user"
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (target_id, username),
  UNIQUE (workspace_id, id),
  FOREIGN KEY (workspace_id, target_id) REFERENCES targets (workspace_id, id) ON DELETE CASCADE
);

-- Exactly one subject column is set. Every reference is scoped to the same
-- workspace and cascades, so a removed member, team, or service account can
-- never leave a grant behind, and no grant can point across tenants.
CREATE TABLE IF NOT EXISTS principal_grants (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  principal_id UUID NOT NULL,
  workspace_id UUID NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
  user_id UUID,
  team_id UUID,
  service_account_id UUID,
  subject_kind TEXT GENERATED ALWAYS AS (
    CASE
      WHEN user_id IS NOT NULL THEN 'user'
      WHEN team_id IS NOT NULL THEN 'team'
      ELSE 'service_account'
    END
  ) STORED,
  subject_id UUID GENERATED ALWAYS AS (COALESCE(user_id, team_id, service_account_id)) STORED,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  FOREIGN KEY (workspace_id, principal_id) REFERENCES principals (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, user_id) REFERENCES workspace_members (workspace_id, user_id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, team_id) REFERENCES teams (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, service_account_id) REFERENCES service_accounts (workspace_id, id) ON DELETE CASCADE,
  UNIQUE NULLS NOT DISTINCT (principal_id, user_id, team_id, service_account_id),
  CHECK (num_nonnulls (user_id, team_id, service_account_id) = 1)
);

CREATE TABLE IF NOT EXISTS recordings (
  id UUID PRIMARY KEY DEFAULT uuidv7(), -- the session id
  workspace_id UUID NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
  daemon_id UUID NOT NULL REFERENCES daemons (id) ON DELETE CASCADE,
  username TEXT NOT NULL,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ended_at TIMESTAMPTZ,
  size_bytes BIGINT NOT NULL DEFAULT 0,
  complete BOOLEAN NOT NULL DEFAULT FALSE, -- False when upload stream ended abruptly
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS saml_keypair (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  key_enc BYTEA NOT NULL,
  cert_pem BYTEA NOT NULL
);

-- Keysets (for envelope encryption - singleton)
CREATE TABLE IF NOT EXISTS keysets (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  data BYTEA NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes --------------------------------------------------------------------
CREATE INDEX idx_workspaces_created_by ON workspaces (created_by);

CREATE INDEX idx_workspace_members_user_id ON workspace_members (user_id, workspace_id);

CREATE INDEX idx_workspace_domains_domain ON workspace_domains (domain);

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

-- One default per authority type per workspace (one SSH, one X509)
CREATE UNIQUE INDEX idx_ca_default_per_workspace ON certificate_authorities (workspace_id, authority_type)
WHERE
  is_default = TRUE;

CREATE INDEX idx_targets_workspace_id ON targets (workspace_id);

CREATE INDEX idx_targets_ca_id ON targets (ca_id);

CREATE INDEX idx_targets_daemon_id ON targets (daemon_id);

CREATE INDEX idx_targets_tags ON targets USING GIN (tags);

CREATE INDEX idx_targets_name_trgm ON targets USING GIN (name gin_trgm_ops);

CREATE INDEX idx_targets_description_trgm ON targets USING GIN (description gin_trgm_ops);

CREATE INDEX idx_principals_workspace_id ON principals (workspace_id);

CREATE INDEX idx_workspace_tokens_workspace ON workspace_tokens (workspace_id, kind);

CREATE INDEX idx_principals_target_id ON principals (target_id);

CREATE INDEX idx_principal_grants_subject ON principal_grants (subject_id);

CREATE INDEX idx_principal_grants_workspace_id ON principal_grants (workspace_id);

CREATE INDEX idx_recordings_workspace_started ON recordings (workspace_id, started_at DESC);

-- An external identity may link to at most one user.
CREATE UNIQUE INDEX idx_credentials_external ON credentials (type, provider, subject)
WHERE
  subject <> '';

CREATE INDEX idx_credentials_user ON credentials (user_id, type);

CREATE INDEX idx_one_time_tokens_expiry ON one_time_tokens (expires_at);

CREATE INDEX idx_scim_tokens_workspace_id ON scim_tokens (workspace_id);

CREATE INDEX idx_sessions_subject ON sessions (subject_id);

CREATE INDEX idx_sessions_workspace ON sessions (workspace_id);

-- SCIM group sync expects displayName to resolve to one group per
-- workspace (RFC 7643). Without this, duplicate pushes create duplicate
-- teams and the IdP's member updates hit the wrong one.
CREATE UNIQUE INDEX IF NOT EXISTS idx_teams_workspace_name ON teams (workspace_id, name);

-- Functions ------------------------------------------------------------------
CREATE OR REPLACE FUNCTION current_workspace_id () RETURNS UUID AS $$
  SELECT NULLIF(current_setting('nokku.workspace_id', TRUE), '')::UUID
$$ LANGUAGE sql STABLE;

CREATE OR REPLACE FUNCTION current_actor_id () RETURNS TEXT AS $$
  SELECT NULLIF(current_setting('nokku.actor_id', TRUE), '')
$$ LANGUAGE sql STABLE;

-- Session helpers ------------------------------------------------------------
-- Membership of the current actor in a workspace. Used for cross-tenant
-- reads users legitimately need outside a pinned workspace.
CREATE OR REPLACE FUNCTION is_workspace_member (ws_id UUID) RETURNS BOOLEAN AS $$
  SELECT EXISTS (
    SELECT 1
    FROM workspace_members wm
    WHERE wm.workspace_id = ws_id
      AND wm.user_id = current_actor_id ()::UUID
  )
$$ LANGUAGE sql STABLE;

-- Triggers -------------------------------------------------------------------
-- Ensure only one default CA per workspace and authority type
CREATE OR REPLACE FUNCTION enforce_single_default_ca () RETURNS TRIGGER AS $$
BEGIN
  IF NEW.is_default = TRUE THEN
    UPDATE certificate_authorities
    SET is_default = FALSE
    WHERE workspace_id = NEW.workspace_id
      AND authority_type = NEW.authority_type
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

-- Daemon state versioning. Any change to what a daemon enforces bumps the
-- workspace version and notifies on commit, so no code path can forget it.
CREATE OR REPLACE FUNCTION create_workspace_state () RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO workspace_state (workspace_id) VALUES (NEW.id);
  RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER
SET
  search_path = public,
  pg_temp;

CREATE TRIGGER create_workspace_state
AFTER INSERT ON workspaces FOR EACH ROW
EXECUTE FUNCTION create_workspace_state ();

CREATE OR REPLACE FUNCTION bump_state_version () RETURNS TRIGGER AS $$
DECLARE
  ws UUID;
BEGIN
  IF TG_OP = 'DELETE' THEN
    ws := OLD.workspace_id;
  ELSE
    ws := NEW.workspace_id;
  END IF;
  UPDATE workspace_state SET version = version + 1 WHERE workspace_id = ws;
  PERFORM pg_notify('nokku_state', ws::TEXT);
  RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER
SET
  search_path = public,
  pg_temp;

CREATE TRIGGER bump_state_version
AFTER INSERT
OR DELETE ON principal_grants FOR EACH ROW
EXECUTE FUNCTION bump_state_version ();

CREATE TRIGGER bump_state_version
AFTER INSERT
OR DELETE ON team_members FOR EACH ROW
EXECUTE FUNCTION bump_state_version ();

-- A new account anchor carries no grants, so only deletes matter.
CREATE TRIGGER bump_state_version
AFTER DELETE ON principals FOR EACH ROW
EXECUTE FUNCTION bump_state_version ();

CREATE TRIGGER bump_state_version
AFTER
UPDATE OF status,
config ON daemons FOR EACH ROW WHEN (
  OLD.status IS DISTINCT FROM NEW.status
  OR OLD.config IS DISTINCT FROM NEW.config
)
EXECUTE FUNCTION bump_state_version ();

CREATE TRIGGER bump_state_version_delete
AFTER DELETE ON daemons FOR EACH ROW
EXECUTE FUNCTION bump_state_version ();

CREATE TRIGGER bump_state_version
AFTER INSERT
OR DELETE ON certificate_authorities FOR EACH ROW
EXECUTE FUNCTION bump_state_version ();

CREATE TRIGGER bump_state_version_update
AFTER
UPDATE OF public_key,
is_active,
is_default ON certificate_authorities FOR EACH ROW WHEN (
  OLD.public_key IS DISTINCT FROM NEW.public_key
  OR OLD.is_active IS DISTINCT FROM NEW.is_active
  OR OLD.is_default IS DISTINCT FROM NEW.is_default
)
EXECUTE FUNCTION bump_state_version ();

CREATE TRIGGER bump_state_version
AFTER
UPDATE OF ca_id ON targets FOR EACH ROW WHEN (OLD.ca_id IS DISTINCT FROM NEW.ca_id)
EXECUTE FUNCTION bump_state_version ();

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

REVOKE INSERT,
UPDATE,
DELETE ON workspace_state
FROM
  nokku_app,
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
-- References to other tenant tables use composite (workspace_id, id) foreign
-- keys, so no policy needs a subquery to keep a row inside its workspace.
ALTER TABLE workspaces ENABLE ROW LEVEL SECURITY;

ALTER TABLE workspaces FORCE ROW LEVEL SECURITY;

ALTER TABLE workspace_members ENABLE ROW LEVEL SECURITY;

ALTER TABLE workspace_members FORCE ROW LEVEL SECURITY;

ALTER TABLE workspace_subscriptions ENABLE ROW LEVEL SECURITY;

ALTER TABLE workspace_subscriptions FORCE ROW LEVEL SECURITY;

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

ALTER TABLE principal_grants ENABLE ROW LEVEL SECURITY;

ALTER TABLE principal_grants FORCE ROW LEVEL SECURITY;

ALTER TABLE recordings ENABLE ROW LEVEL SECURITY;

ALTER TABLE recordings FORCE ROW LEVEL SECURITY;

ALTER TABLE sso_providers ENABLE ROW LEVEL SECURITY;

ALTER TABLE sso_providers FORCE ROW LEVEL SECURITY;

ALTER TABLE scim_tokens ENABLE ROW LEVEL SECURITY;

ALTER TABLE scim_tokens FORCE ROW LEVEL SECURITY;

ALTER TABLE workspace_tokens ENABLE ROW LEVEL SECURITY;

ALTER TABLE workspace_tokens FORCE ROW LEVEL SECURITY;

ALTER TABLE workspace_domains ENABLE ROW LEVEL SECURITY;

ALTER TABLE workspace_domains FORCE ROW LEVEL SECURITY;

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
    OR user_id = current_actor_id ()::UUID
  );

CREATE POLICY workspace_members_write ON workspace_members FOR ALL TO nokku_app USING (workspace_id = current_workspace_id ())
WITH
  CHECK (workspace_id = current_workspace_id ());

-- Pure tenant tables ---------------------------------------------------------
CREATE POLICY tenant_isolation ON workspace_subscriptions FOR ALL TO nokku_app USING (workspace_id = current_workspace_id ())
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

-- Global providers (workspace_id NULL) are readable by everyone and written
-- only by nokku_system.
CREATE POLICY sso_providers_select ON sso_providers FOR
SELECT
  TO nokku_app USING (
    workspace_id IS NULL
    OR workspace_id = current_workspace_id ()
  );

CREATE POLICY tenant_isolation ON sso_providers FOR ALL TO nokku_app USING (workspace_id = current_workspace_id ())
WITH
  CHECK (workspace_id = current_workspace_id ());

CREATE POLICY tenant_isolation ON scim_tokens FOR ALL TO nokku_app USING (workspace_id = current_workspace_id ())
WITH
  CHECK (workspace_id = current_workspace_id ());

CREATE POLICY tenant_isolation ON workspace_tokens FOR ALL TO nokku_app USING (workspace_id = current_workspace_id ())
WITH
  CHECK (workspace_id = current_workspace_id ());

CREATE POLICY tenant_isolation ON workspace_domains FOR ALL TO nokku_app USING (workspace_id = current_workspace_id ())
WITH
  CHECK (workspace_id = current_workspace_id ());

-- Composite foreign keys keep every reference inside one workspace, so these
-- need nothing beyond the uniform policy.
CREATE POLICY tenant_isolation ON team_members FOR ALL TO nokku_app USING (workspace_id = current_workspace_id ())
WITH
  CHECK (workspace_id = current_workspace_id ());

CREATE POLICY tenant_isolation ON principal_grants FOR ALL TO nokku_app USING (workspace_id = current_workspace_id ())
WITH
  CHECK (workspace_id = current_workspace_id ());

-- Identity tables ------------------------------------------------------------
-- Users are global, so the tenant GUC alone cannot scope them. The app role
-- sees a user only as themselves or as a member of the pinned workspace, and
-- writes only its own row. Credentials and sessions are private to their
-- owner. Login, signup, and SCIM run as nokku_system. Tokens and key
-- material have no app policy at all.
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

ALTER TABLE users FORCE ROW LEVEL SECURITY;

ALTER TABLE credentials ENABLE ROW LEVEL SECURITY;

ALTER TABLE credentials FORCE ROW LEVEL SECURITY;

ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;

ALTER TABLE sessions FORCE ROW LEVEL SECURITY;

ALTER TABLE one_time_tokens ENABLE ROW LEVEL SECURITY;

ALTER TABLE one_time_tokens FORCE ROW LEVEL SECURITY;

ALTER TABLE keysets ENABLE ROW LEVEL SECURITY;

ALTER TABLE keysets FORCE ROW LEVEL SECURITY;

ALTER TABLE saml_keypair ENABLE ROW LEVEL SECURITY;

ALTER TABLE saml_keypair FORCE ROW LEVEL SECURITY;

CREATE POLICY users_select ON users FOR
SELECT
  TO nokku_app USING (
    id = current_actor_id ()::UUID
    OR EXISTS (
      SELECT
        1
      FROM
        workspace_members wm
      WHERE
        wm.user_id = users.id
        AND wm.workspace_id = current_workspace_id ()
    )
  );

CREATE POLICY users_update ON users
FOR UPDATE
  TO nokku_app USING (id = current_actor_id ()::UUID)
WITH
  CHECK (id = current_actor_id ()::UUID);

CREATE POLICY credentials_owner ON credentials FOR ALL TO nokku_app USING (user_id = current_actor_id ()::UUID)
WITH
  CHECK (user_id = current_actor_id ()::UUID);

CREATE POLICY sessions_owner ON sessions FOR ALL TO nokku_app USING (subject_id = current_actor_id ())
WITH
  CHECK (subject_id = current_actor_id ());

-- Audit schema ---------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS audit;

-- One row per thing that happened. A row with a workspace belongs to that
-- workspace's log, and every row also shows in its actor's personal log.
-- workspace_id has no foreign key: the log outlives a deleted workspace, and
-- the append-only trigger would refuse an ON DELETE SET NULL anyway.
CREATE TABLE IF NOT EXISTS audit.audit_logs (
  id UUID NOT NULL DEFAULT uuidv7(),
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  workspace_id UUID,
  actor_id TEXT NOT NULL DEFAULT '',
  actor_kind TEXT NOT NULL DEFAULT '',
  actor_name TEXT NOT NULL DEFAULT '', -- email or name at the time
  action TEXT NOT NULL, -- RPC method name or iam action, e.g. DeleteTarget, Login
  target TEXT NOT NULL DEFAULT '', -- the resource the action was about
  ok BOOLEAN NOT NULL,
  ip TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT '',
  details JSONB NOT NULL DEFAULT '{}',
  PRIMARY KEY (timestamp, id)
)
PARTITION BY
  RANGE (timestamp);

CREATE INDEX IF NOT EXISTS idx_audit_logs_workspace_time ON audit.audit_logs (workspace_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit.audit_logs (actor_id, timestamp DESC);

CREATE POLICY audit_logs_select ON audit.audit_logs FOR
SELECT
  TO nokku_app USING (
    workspace_id = current_workspace_id ()
    OR actor_id = current_actor_id ()
  );

-- Access for the application roles
GRANT USAGE ON SCHEMA audit TO nokku_app,
nokku_system;

-- nokku_app reads its own workspace's events. Writes go through nokku_system.
GRANT
SELECT
  ON ALL TABLES IN SCHEMA audit TO nokku_app;

-- nokku_system additionally can DELETE (partition cleanup)
GRANT
SELECT
,
  INSERT,
  DELETE ON ALL TABLES IN SCHEMA audit TO nokku_system;

-- Partitions created later by the retention job inherit these.
ALTER DEFAULT PRIVILEGES IN SCHEMA audit
GRANT
SELECT
  ON TABLES TO nokku_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA audit
GRANT
SELECT
,
  INSERT,
  DELETE ON TABLES TO nokku_system;

ALTER TABLE audit.audit_logs ENABLE ROW LEVEL SECURITY;

ALTER TABLE audit.audit_logs FORCE ROW LEVEL SECURITY;

-- Audit immutability ---------------------------------------------------------
-- An audit row is a fact that is only ever written. Two layers keep it that
-- way, and the honest division of labour is:
--
--   UPDATE is denied by privilege. No role holds UPDATE on this table.
--   DELETE is refused by this trigger unless the transaction opts in, which
--   only the retention job does. The app role inherits DELETE from
--   nokku_system, so this trigger is what actually stops a delete that can
--   reach rows.
--   The app role cannot reach rows at all: RLS is enabled and forced on this
--   table and there is no DELETE policy, so a DELETE from nokku_app matches
--   zero rows regardless of privilege. Do not add a DELETE policy. If one is
--   ever needed, the trigger's opt-in must stop being a plain GUC.
--
-- The trigger sits on the partitioned parent, so every partition, including
-- the ones the retention job creates later, inherits it.
CREATE OR REPLACE FUNCTION audit.audit_logs_immutable () RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'audit.audit_logs is append-only, update denied';
  END IF;
  IF coalesce(current_setting('nokku.audit_retention', true), '') <> 'on' THEN
    RAISE EXCEPTION 'audit.audit_logs is append-only, delete denied';
  END IF;
  RETURN OLD;
END $$;

CREATE TRIGGER audit_logs_immutable BEFORE
UPDATE
OR DELETE ON audit.audit_logs FOR EACH ROW
EXECUTE FUNCTION audit.audit_logs_immutable ();

-- Audit partitions ------------------------------------------------------------
-- Monthly partitions are DDL, which needs the table owner. This function runs
-- as the owner so the runtime roles never need owner rights. It keeps the
-- previous, current, and next UTC month, and drops partitions older than 14
-- months (the longest retention plus margin).
CREATE OR REPLACE FUNCTION audit.maintain_partitions () RETURNS VOID AS $$
DECLARE
  this_month TIMESTAMP := date_trunc('month', now() AT TIME ZONE 'UTC');
  m TIMESTAMP;
  part TEXT;
BEGIN
  IF NOT pg_try_advisory_xact_lock(hashtext('audit-partitions')) THEN
    RETURN;
  END IF;
  FOR i IN -1..1 LOOP
    m := this_month + make_interval(months => i);
    EXECUTE format(
      'CREATE TABLE IF NOT EXISTS audit.%I PARTITION OF audit.audit_logs FOR VALUES FROM (%L) TO (%L)',
      to_char(m, '"audit_logs_y"YYYY"m"MM'),
      m AT TIME ZONE 'UTC',
      (m + INTERVAL '1 month') AT TIME ZONE 'UTC'
    );
  END LOOP;
  FOR part IN
    SELECT c.relname
    FROM pg_inherits inh
      JOIN pg_class c ON c.oid = inh.inhrelid
    WHERE inh.inhparent = 'audit.audit_logs'::REGCLASS
      AND c.relname < to_char(this_month - INTERVAL '14 months', '"audit_logs_y"YYYY"m"MM')
  LOOP
    EXECUTE format('DROP TABLE IF EXISTS audit.%I', part);
  END LOOP;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER
SET
  search_path = audit,
  public,
  pg_temp;

REVOKE ALL ON FUNCTION audit.maintain_partitions ()
FROM
  PUBLIC;

GRANT
EXECUTE ON FUNCTION audit.maintain_partitions () TO nokku_system;

SELECT
  audit.maintain_partitions ();
