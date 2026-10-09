-- Base schema for nokku.
--
-- The workspace is the tenant. Every other table hangs off one, users
-- included, and one row-level security policy keeps them apart. A
-- self-hosted server has exactly one workspace.
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- The workspace a connection is pinned to, NULL when none is. The row-level
-- security policies compare against it, and every tenant table takes its
-- workspace_id from it by default, so an insert never names the workspace.
-- Unpinned, the default is NULL and the insert fails on NOT NULL.
CREATE OR REPLACE FUNCTION current_workspace_id () RETURNS UUID AS $$
  SELECT NULLIF(current_setting('nokku.workspace_id', TRUE), '')::UUID
$$ LANGUAGE sql STABLE;

CREATE TABLE IF NOT EXISTS workspaces (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  -- The subdomain on the hosted service. Self-host has one workspace and
  -- never looks at it.
  slug TEXT NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
  name TEXT NOT NULL,
  description TEXT,
  settings JSONB NOT NULL DEFAULT '{}',
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

CREATE TABLE IF NOT EXISTS workspace_subscriptions (
  workspace_id UUID PRIMARY KEY DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  source TEXT NOT NULL DEFAULT '', -- stripe, manual, ...
  plan TEXT NOT NULL DEFAULT '', -- community, pro, enterprise
  status TEXT NOT NULL DEFAULT '',
  customer_id TEXT NOT NULL DEFAULT '', -- stripe customer id, opaque
  subscription_id TEXT NOT NULL DEFAULT '', -- stripe subscription id, opaque
  current_period_end TIMESTAMPTZ,
  cancel_at_period_end BOOLEAN NOT NULL DEFAULT FALSE,
  seats BIGINT NOT NULL DEFAULT 0, -- paid quantity, 0 = the plan's own cap
  ended_at TIMESTAMPTZ, -- set once the subscription is over, starts the retention hold
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Identity --------------------------------------------------------------------
-- A user belongs to one workspace. The same person at two companies has two
-- rows, one per workspace, and each company fully owns theirs.
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  email TEXT NOT NULL CHECK (email = lower(email)),
  name TEXT NOT NULL DEFAULT '',
  picture TEXT,
  -- WorkspaceRole of the protos: 1=member, 2=viewer, 3=editor, 4=admin,
  -- 5=owner. Ordered, each includes everything before it.
  role INTEGER NOT NULL DEFAULT 1 CHECK (role BETWEEN 1 AND 5),
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, email),
  UNIQUE (workspace_id, id)
);

-- Exactly one owner per workspace. TransferOwnership swaps the roles in one
-- statement, anything else trips this index.
CREATE UNIQUE INDEX idx_users_owner ON users (workspace_id)
WHERE
  role = 5;

CREATE TABLE IF NOT EXISTS credentials (
  id TEXT PRIMARY KEY, -- webauthn credential id, or uuidv7
  workspace_id UUID NOT NULL DEFAULT current_workspace_id (),
  user_id UUID NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('passkey', 'oidc', 'scim')),
  provider TEXT NOT NULL DEFAULT '', -- the sso provider id for oidc
  subject TEXT NOT NULL DEFAULT '', -- the external identity
  data BYTEA NOT NULL DEFAULT '',
  label TEXT NOT NULL DEFAULT '',
  last_used_at TIMESTAMPTZ, -- last successful sign-in with it
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  FOREIGN KEY (workspace_id, user_id) REFERENCES users (workspace_id, id) ON DELETE CASCADE
);

-- An external identity links to at most one user of the workspace.
CREATE UNIQUE INDEX idx_credentials_external ON credentials (workspace_id, type, provider, subject)
WHERE
  subject <> '';

CREATE INDEX idx_credentials_user ON credentials (user_id, type);

-- Links sent by mail. A signup token has no user yet, the account is created
-- when it is spent.
CREATE TABLE IF NOT EXISTS one_time_tokens (
  token_hash TEXT PRIMARY KEY,
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  user_id UUID,
  purpose TEXT NOT NULL CHECK (purpose IN ('login', 'signup', 'email_change', 'email_revert')),
  email TEXT CHECK (email = lower(email)),
  data JSONB NOT NULL DEFAULT '{}', -- signup: name, role, invite id
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK ((purpose = 'signup') = (user_id IS NULL)),
  FOREIGN KEY (workspace_id, user_id) REFERENCES users (workspace_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_one_time_tokens_expiry ON one_time_tokens (expires_at);

CREATE INDEX idx_one_time_tokens_user ON one_time_tokens (user_id, purpose);

-- Browsers and terminals an account has signed in from. They show in the
-- "where you're signed in" list, and a sign-in from one that is not here
-- yet is mailed to the account. A row never signs anyone in.
CREATE TABLE IF NOT EXISTS known_devices (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  user_id UUID NOT NULL,
  -- What the device is recognized by: the hash of a browser's device
  -- cookie, or the DPoP key thumbprint of a terminal.
  key TEXT NOT NULL,
  ip TEXT NOT NULL DEFAULT '', -- of the sign-in that added it
  user_agent TEXT NOT NULL DEFAULT '', -- of the sign-in that added it
  expires_at TIMESTAMPTZ NOT NULL,
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, user_id, key),
  FOREIGN KEY (workspace_id, user_id) REFERENCES users (workspace_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_known_devices_expiry ON known_devices (expires_at);

-- OIDC providers of the workspace. The config, secret included, is one JSON
-- blob encrypted at rest.
CREATE TABLE IF NOT EXISTS sso_providers (
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  provider_id TEXT NOT NULL CHECK (provider_id ~ '^[a-z0-9-]{1,64}$'),
  name TEXT NOT NULL DEFAULT '',
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  config BYTEA NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (workspace_id, provider_id)
);

-- Access ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS service_accounts (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  name TEXT NOT NULL, -- e.g., "github-actions-deploy", "ansible-prod"
  description TEXT,
  role INTEGER NOT NULL DEFAULT 1 CHECK (role BETWEEN 1 AND 3), -- like users.role, the editor at most
  last_used_at TIMESTAMPTZ, -- of any of its tokens, kept by note_service_account_used
  tags TEXT[] NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, name),
  UNIQUE (workspace_id, id)
);

-- Everything that authenticates a call: browser and CLI sessions, daemon
-- sessions, service account keys, SCIM tokens. Every row is a credential.
-- What only remembers a device lives in known_devices, so nothing here ever
-- has to be told apart from a login.
CREATE TABLE IF NOT EXISTS access_tokens (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  token_hash TEXT NOT NULL UNIQUE,
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('user', 'cli', 'daemon', 'service_account', 'scim')),
  -- One subject column per kind, none for scim. A daemon's token has to
  -- outlive the daemon: it is what the host gets its REJECTED answer
  -- through, and SyncDaemon removes it with that answer, so no foreign key.
  user_id UUID,
  service_account_id UUID,
  daemon_id UUID,
  subject_id UUID GENERATED ALWAYS AS (COALESCE(user_id, service_account_id, daemon_id)) STORED,
  method TEXT NOT NULL, -- passkey, magic_link, oidc, device, token, scim
  binding TEXT NOT NULL DEFAULT '', -- DPoP JWK thumbprint, empty for cookie sessions and keys
  label TEXT NOT NULL DEFAULT '', -- the name the new sign-in mail gives a terminal, or the key's label
  ip TEXT NOT NULL DEFAULT '', -- of the request that created the token
  user_agent TEXT NOT NULL DEFAULT '', -- of the request that created the token
  expires_at TIMESTAMPTZ, -- NULL never expires (daemons re-auth via DPoP proofs)
  last_seen_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  FOREIGN KEY (workspace_id, user_id) REFERENCES users (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, service_account_id) REFERENCES service_accounts (workspace_id, id) ON DELETE CASCADE,
  CHECK (num_nonnulls (user_id, service_account_id, daemon_id) <= 1),
  CHECK ((kind = 'scim') = (num_nonnulls (user_id, service_account_id, daemon_id) = 0)),
  CHECK ((kind IN ('user', 'cli')) = (user_id IS NOT NULL)),
  CHECK ((kind = 'daemon') = (daemon_id IS NOT NULL)),
  CHECK ((kind = 'service_account') = (service_account_id IS NOT NULL))
);

CREATE INDEX idx_access_tokens_subject ON access_tokens (subject_id);

CREATE INDEX idx_access_tokens_workspace ON access_tokens (workspace_id);

CREATE INDEX idx_access_tokens_expiry ON access_tokens (expires_at)
WHERE
  expires_at IS NOT NULL;

-- The account remembers when any of its tokens was last used, so a list of
-- accounts needs no join. The stamp moves at most once a minute per token.
CREATE OR REPLACE FUNCTION note_service_account_used () RETURNS TRIGGER AS $$
BEGIN
  UPDATE service_accounts
  SET last_used_at = GREATEST(last_used_at, NEW.last_seen_at)
  WHERE id = NEW.service_account_id;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER note_service_account_used
AFTER
UPDATE OF last_seen_at ON access_tokens FOR EACH ROW WHEN (NEW.service_account_id IS NOT NULL)
EXECUTE FUNCTION note_service_account_used ();

CREATE TABLE IF NOT EXISTS daemons (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  status INTEGER NOT NULL DEFAULT 1 CHECK (status IN (1, 2, 3)), -- 1=pending, 2=accepted, 3=rejected
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
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  tags TEXT[] NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, id)
);

CREATE TABLE IF NOT EXISTS team_members (
  workspace_id UUID NOT NULL DEFAULT current_workspace_id (),
  user_id UUID NOT NULL,
  team_id UUID NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (user_id, team_id),
  FOREIGN KEY (workspace_id, user_id) REFERENCES users (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, team_id) REFERENCES teams (workspace_id, id) ON DELETE CASCADE
);

-- SSH certificate authorities. An X.509 CA, when there is one, gets a table
-- of its own: it shares the key material and nothing else.
CREATE TABLE IF NOT EXISTS ssh_cas (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  private_key BYTEA NOT NULL, -- Encrypted private key
  public_key TEXT NOT NULL, -- OpenSSH wire format
  previous_public_key TEXT, -- the key before the last rollover
  previous_trusted_until TIMESTAMPTZ, -- its certificates are trusted until then
  not_before TIMESTAMPTZ NOT NULL,
  not_after TIMESTAMPTZ NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  is_default BOOLEAN NOT NULL DEFAULT FALSE,
  key_type INTEGER NOT NULL DEFAULT 3, -- 1 = RSA, 2 = ECDSA, 3 = ED25519
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
  CHECK (user_default_ttl <= user_max_ttl),
  CHECK (host_default_ttl <= host_max_ttl)
);

CREATE TABLE IF NOT EXISTS targets (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
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
  FOREIGN KEY (workspace_id, ca_id) REFERENCES ssh_cas (workspace_id, id) ON DELETE SET NULL (ca_id),
  FOREIGN KEY (workspace_id, daemon_id) REFERENCES daemons (workspace_id, id) ON DELETE CASCADE
);

-- Join tokens. Enroll tokens bring daemons in, invite tokens bring people
-- in. The plaintext is "<id>_<secret>", so redemption looks the row up by id
-- and compares the hash of the whole token.
CREATE TABLE IF NOT EXISTS join_tokens (
  id UUID PRIMARY KEY,
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  kind INTEGER NOT NULL CHECK (kind IN (1, 2)), -- 1=enroll, 2=invite
  label TEXT NOT NULL DEFAULT '',
  token_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ, -- NULL never expires
  max_uses INTEGER CHECK (max_uses > 0), -- NULL is unlimited
  uses INTEGER NOT NULL DEFAULT 0,
  auto_approve BOOLEAN NOT NULL DEFAULT FALSE, -- enroll only
  ca_id UUID, -- enroll only, NULL is the workspace default
  role INTEGER CHECK (role BETWEEN 1 AND 4), -- invite only, like users.role, never the owner
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at TIMESTAMPTZ,
  FOREIGN KEY (workspace_id, ca_id) REFERENCES ssh_cas (workspace_id, id) ON DELETE SET NULL (ca_id),
  CHECK (
    kind = 1
    OR (
      NOT auto_approve
      AND ca_id IS NULL
    )
  ),
  CHECK ((kind = 2) = (role IS NOT NULL))
);

-- A local account on a target, like root or deploy. Grants hang off it.
CREATE TABLE IF NOT EXISTS target_accounts (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  target_id UUID NOT NULL,
  username TEXT NOT NULL DEFAULT 'root', -- e.g. "root", "ubuntu", "ec2-user"
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (target_id, username),
  UNIQUE (workspace_id, id),
  FOREIGN KEY (workspace_id, target_id) REFERENCES targets (workspace_id, id) ON DELETE CASCADE
);

-- Exactly one subject column is set. Every reference is scoped to the same
-- workspace and cascades, so a removed user, team, or service account can
-- never leave a grant behind, and no grant can point across tenants.
CREATE TABLE IF NOT EXISTS grants (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  account_id UUID NOT NULL,
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
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
  FOREIGN KEY (workspace_id, account_id) REFERENCES target_accounts (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, user_id) REFERENCES users (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, team_id) REFERENCES teams (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, service_account_id) REFERENCES service_accounts (workspace_id, id) ON DELETE CASCADE,
  UNIQUE NULLS NOT DISTINCT (account_id, user_id, team_id, service_account_id),
  CHECK (num_nonnulls (user_id, team_id, service_account_id) = 1)
);

CREATE TABLE IF NOT EXISTS recordings (
  id UUID PRIMARY KEY DEFAULT uuidv7(), -- the session id
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  -- A recording outlives its daemon, only retention deletes it.
  daemon_id UUID REFERENCES daemons (id) ON DELETE SET NULL,
  daemon_name TEXT NOT NULL, -- as it was when the session ran
  username TEXT NOT NULL,
  -- Who was logged in. The host reports the certificate principal it matched,
  -- the subject is parsed out of it. NULL from a daemon that did not say.
  subject_id UUID,
  principal TEXT NOT NULL DEFAULT '',
  key BYTEA NOT NULL, -- encrypts this recording's frames, stored encrypted
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ended_at TIMESTAMPTZ,
  size_bytes BIGINT NOT NULL DEFAULT 0,
  complete BOOLEAN NOT NULL DEFAULT FALSE, -- False when upload stream ended abruptly
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Instance -------------------------------------------------------------------
-- The one keyset that encrypts everything at rest, wrapped by a key derived
-- from NOKKU_SECRET or by the KMS key. rotated_at is when it last got a new
-- primary key.
CREATE TABLE IF NOT EXISTS keysets (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  data BYTEA NOT NULL,
  rotated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- License key activated in the UI (singleton). NOKKU_LICENSE_KEY still works,
-- the key that is valid longest wins.
CREATE TABLE IF NOT EXISTS instance_license (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  key TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The CA of NOKKU_TLS=internal (singleton). The key stays for good, so the
-- pin clients hold never changes. The certificate is issued again when the
-- host name changes or it nears its end.
CREATE TABLE IF NOT EXISTS web_ca (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  private_key BYTEA NOT NULL,
  certificate BYTEA NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes --------------------------------------------------------------------
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

-- SCIM group sync expects displayName to resolve to one group per
-- workspace (RFC 7643). Without this, duplicate pushes create duplicate
-- teams and the IdP's member updates hit the wrong one.
CREATE UNIQUE INDEX idx_teams_workspace_name ON teams (workspace_id, name);

CREATE INDEX idx_team_members_team_id ON team_members (team_id);

CREATE INDEX idx_ssh_cas_workspace_id ON ssh_cas (workspace_id);

CREATE INDEX idx_ssh_cas_name_trgm ON ssh_cas USING GIN (name gin_trgm_ops);

-- One default per workspace. SetDefaultCA moves it in one statement.
CREATE UNIQUE INDEX idx_ssh_cas_default ON ssh_cas (workspace_id)
WHERE
  is_default = TRUE;

CREATE INDEX idx_targets_workspace_id ON targets (workspace_id);

CREATE INDEX idx_targets_ca_id ON targets (ca_id);

CREATE INDEX idx_targets_daemon_id ON targets (daemon_id);

CREATE INDEX idx_targets_tags ON targets USING GIN (tags);

CREATE INDEX idx_targets_name_trgm ON targets USING GIN (name gin_trgm_ops);

CREATE INDEX idx_targets_description_trgm ON targets USING GIN (description gin_trgm_ops);

CREATE INDEX idx_join_tokens_workspace ON join_tokens (workspace_id, kind);

CREATE INDEX idx_target_accounts_workspace_id ON target_accounts (workspace_id);

CREATE INDEX idx_target_accounts_target_id ON target_accounts (target_id);

CREATE INDEX idx_grants_subject ON grants (subject_id);

CREATE INDEX idx_grants_workspace_id ON grants (workspace_id);

CREATE INDEX idx_recordings_workspace_started ON recordings (workspace_id, started_at DESC);

CREATE INDEX idx_recordings_subject ON recordings (workspace_id, subject_id, started_at DESC);

-- Triggers -------------------------------------------------------------------
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
OR DELETE ON grants FOR EACH ROW
EXECUTE FUNCTION bump_state_version ();

CREATE TRIGGER bump_state_version
AFTER INSERT
OR DELETE ON team_members FOR EACH ROW
EXECUTE FUNCTION bump_state_version ();

-- A new account carries no grants, so only deletes matter.
CREATE TRIGGER bump_state_version
AFTER DELETE ON target_accounts FOR EACH ROW
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
OR DELETE ON ssh_cas FOR EACH ROW
EXECUTE FUNCTION bump_state_version ();

CREATE TRIGGER bump_state_version_update
AFTER
UPDATE OF public_key,
is_active,
is_default ON ssh_cas FOR EACH ROW WHEN (
  OLD.public_key IS DISTINCT FROM NEW.public_key
  OR OLD.is_active IS DISTINCT FROM NEW.is_active
  OR OLD.is_default IS DISTINCT FROM NEW.is_default
)
EXECUTE FUNCTION bump_state_version ();

CREATE TRIGGER bump_state_version
AFTER
UPDATE OF ca_id ON targets FOR EACH ROW WHEN (OLD.ca_id IS DISTINCT FROM NEW.ca_id)
EXECUTE FUNCTION bump_state_version ();

-- A deactivated account must leave every daemon's map at once.
CREATE TRIGGER bump_state_version
AFTER
UPDATE OF active ON users FOR EACH ROW WHEN (OLD.active IS DISTINCT FROM NEW.active)
EXECUTE FUNCTION bump_state_version ();

-- Console hints. A change to what the console shows is announced on commit as
-- "<workspace id>:<table>", and internal/live tells the open consoles of that
-- workspace to read again. It carries no data. The same payload twice in one
-- transaction arrives once, so a bulk write is one hint.
CREATE OR REPLACE FUNCTION notify_change () RETURNS TRIGGER AS $$
DECLARE
  r JSONB;
BEGIN
  IF TG_OP = 'DELETE' THEN
    r := to_jsonb(OLD);
  ELSE
    r := to_jsonb(NEW);
  END IF;
  -- workspaces has no workspace_id, its id is one.
  PERFORM pg_notify('nokku_change', COALESCE(r ->> 'workspace_id', r ->> 'id') || ':' || TG_TABLE_NAME);
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Stamps that move on a timer or with every use. An update that moves
-- nothing else is not a change anyone waits for.
CREATE OR REPLACE FUNCTION without_stamps (r JSONB) RETURNS JSONB AS $$
  SELECT (r - ARRAY['last_seen_at', 'last_used_at']) #- '{metadata,last_manual_sync}'
$$ LANGUAGE sql IMMUTABLE;

-- Sign-ins are left out (access_tokens, known_devices, credentials,
-- one_time_tokens). They happen all day and no list shows them to others.
-- Service account keys and SCIM tokens are the exception, they are made and
-- revoked by hand and a list shows them, see the triggers after the loop.
DO $$
DECLARE
  t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'workspaces',
    'workspace_subscriptions',
    'users',
    'sso_providers',
    'join_tokens',
    'service_accounts',
    'daemons',
    'teams',
    'team_members',
    'ssh_cas',
    'targets',
    'target_accounts',
    'grants',
    'recordings'
  ] LOOP
    EXECUTE format(
      'CREATE TRIGGER notify_change AFTER INSERT OR DELETE ON %I
         FOR EACH ROW EXECUTE FUNCTION notify_change ()',
      t
    );
    EXECUTE format(
      'CREATE TRIGGER notify_change_update AFTER UPDATE ON %I
         FOR EACH ROW WHEN (without_stamps (to_jsonb(OLD)) IS DISTINCT FROM without_stamps (to_jsonb(NEW)))
         EXECUTE FUNCTION notify_change ()',
      t
    );
  END LOOP;
END $$;

CREATE TRIGGER notify_change_insert
AFTER INSERT ON access_tokens FOR EACH ROW WHEN (NEW.kind IN ('service_account', 'scim'))
EXECUTE FUNCTION notify_change ();

CREATE TRIGGER notify_change_delete
AFTER DELETE ON access_tokens FOR EACH ROW WHEN (OLD.kind IN ('service_account', 'scim'))
EXECUTE FUNCTION notify_change ();

-- The heartbeat stamps a connected daemon every ten seconds, so a gap wider
-- than the online window means this stamp brings it online. Going offline is
-- no write, the daemon pool announces that one.
CREATE TRIGGER notify_online
AFTER
UPDATE OF last_seen_at ON daemons FOR EACH ROW WHEN (
  OLD.last_seen_at IS NULL
  OR NEW.last_seen_at - OLD.last_seen_at > INTERVAL '30 seconds'
)
EXECUTE FUNCTION notify_change ();

-- Roles and grants -----------------------------------------------------------
-- Two runtime roles, each with a pool of its own. nokku_app serves requests
-- under row-level security, nokku_system bypasses it for work that spans
-- workspaces. Neither is a member of the other, so a request connection
-- cannot leave row-level security. Both get their password at start, see
-- setupRoles in internal/db/connection.go.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nokku_app') THEN
    CREATE ROLE nokku_app NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nokku_system') THEN
    CREATE ROLE nokku_system NOLOGIN BYPASSRLS;
  END IF;
END $$;

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
-- One policy on every tenant table: a row is visible and writable only when
-- the connection is pinned to its workspace in the GUC "nokku.workspace_id".
-- The backend sets it every time a connection leaves the request pool (see
-- pinWorkspace in internal/db/connection.go). That is session state, so the
-- backend needs direct connections, not a pooler in transaction mode.
--
-- Fail-closed properties:
--   - The application connects as nokku_app, which does not own the tables,
--     so RLS applies to every query; FORCE ROW LEVEL SECURITY extends this
--     to the table owner as well.
--   - An unset GUC makes current_workspace_id() return NULL, and
--     "workspace_id = NULL" matches nothing, so tenant tables are empty by
--     default.
--   - Cross-tenant work (boot, billing webhooks, background jobs) runs as
--     nokku_system, which has BYPASSRLS. That is a pool of its own and
--     explicit in code (Connection.Sys and SysTx).
--
-- The policy is the only tenant filter there is. Tenant queries name no
-- workspace, and inserts take workspace_id from its column default. A new
-- workspace is created in a transaction pinned to the id it is about to get.
--
-- A new tenant table needs its name in the list below and the default on
-- workspace_id, internal/db/rls_test.go fails without either. References to
-- other tenant tables use composite (workspace_id, id) foreign keys, so no
-- policy needs a subquery to keep a row inside its workspace. keysets,
-- instance_license, web_ca and workspace_state have no app policy,
-- nokku_system alone reaches them.
DO $$
DECLARE
  t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'users',
    'credentials',
    'access_tokens',
    'known_devices',
    'one_time_tokens',
    'sso_providers',
    'workspace_subscriptions',
    'join_tokens',
    'service_accounts',
    'daemons',
    'teams',
    'team_members',
    'ssh_cas',
    'targets',
    'target_accounts',
    'grants',
    'recordings'
  ] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I FOR ALL TO nokku_app
         USING (workspace_id = current_workspace_id())
         WITH CHECK (workspace_id = current_workspace_id())',
      t
    );
  END LOOP;
END $$;

ALTER TABLE workspaces ENABLE ROW LEVEL SECURITY;

ALTER TABLE workspaces FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON workspaces FOR ALL TO nokku_app USING (id = current_workspace_id ())
WITH
  CHECK (id = current_workspace_id ());

ALTER TABLE keysets ENABLE ROW LEVEL SECURITY;

ALTER TABLE keysets FORCE ROW LEVEL SECURITY;

ALTER TABLE instance_license ENABLE ROW LEVEL SECURITY;

ALTER TABLE instance_license FORCE ROW LEVEL SECURITY;

ALTER TABLE web_ca ENABLE ROW LEVEL SECURITY;

ALTER TABLE web_ca FORCE ROW LEVEL SECURITY;

-- Audit schema ---------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS audit;

-- One row per thing that happened, filed under the workspace it happened in.
-- workspace_id has no foreign key: the log outlives a deleted workspace, and
-- the append-only trigger would refuse an ON DELETE anyway.
CREATE TABLE IF NOT EXISTS audit.audit_logs (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  workspace_id UUID NOT NULL,
  actor_id TEXT NOT NULL DEFAULT '',
  actor_kind TEXT NOT NULL DEFAULT '',
  actor_name TEXT NOT NULL DEFAULT '', -- email or name at the time
  action TEXT NOT NULL, -- RPC method name or iam action, e.g. DeleteTarget, Login
  target TEXT NOT NULL DEFAULT '', -- the resource the action was about
  ok BOOLEAN NOT NULL,
  ip TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT '',
  details JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_workspace_time ON audit.audit_logs (workspace_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit.audit_logs (workspace_id, actor_id, timestamp DESC);

-- For the retention delete. Rows arrive in time order, so a block range
-- index stays tiny.
CREATE INDEX IF NOT EXISTS idx_audit_logs_time ON audit.audit_logs USING brin (timestamp);

CREATE POLICY tenant_isolation ON audit.audit_logs FOR
SELECT
  TO nokku_app USING (workspace_id = current_workspace_id ());

-- Access for the application roles
GRANT USAGE ON SCHEMA audit TO nokku_app,
nokku_system;

-- nokku_app reads its own workspace's events. Writes go through nokku_system.
GRANT
SELECT
  ON ALL TABLES IN SCHEMA audit TO nokku_app;

-- nokku_system additionally can DELETE, for the retention job.
GRANT
SELECT
,
  INSERT,
  DELETE ON ALL TABLES IN SCHEMA audit TO nokku_system;

ALTER TABLE audit.audit_logs ENABLE ROW LEVEL SECURITY;

ALTER TABLE audit.audit_logs FORCE ROW LEVEL SECURITY;

-- Audit immutability ---------------------------------------------------------
-- An audit row is a fact that is only ever written. Two layers keep it that
-- way:
--
--   Privilege. The app role holds SELECT and nothing else. nokku_system
--   holds INSERT and DELETE. No role holds UPDATE on this table.
--   This trigger. It refuses a DELETE unless the transaction opts in, which
--   only the retention job does.
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
