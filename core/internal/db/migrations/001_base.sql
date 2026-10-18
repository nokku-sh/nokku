CREATE FUNCTION current_workspace_id () RETURNS UUID AS $$
  SELECT NULLIF(current_setting('nokku.workspace_id', TRUE), '')::UUID
$$ LANGUAGE sql STABLE;

CREATE TABLE workspaces (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  slug TEXT NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
  name TEXT NOT NULL,
  description TEXT,
  settings JSONB NOT NULL DEFAULT '{}',
  -- Members may ask access for the targets with one of these tags.
  requestable_tags TEXT[] NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Bumped by triggers whenever what a daemon enforces changes. No RLS
CREATE TABLE workspace_state (
  workspace_id UUID PRIMARY KEY REFERENCES workspaces (id) ON DELETE CASCADE,
  version BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE workspace_subscriptions (
  workspace_id UUID PRIMARY KEY DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  source TEXT NOT NULL DEFAULT '', -- stripe, trial, manual, ...
  plan TEXT NOT NULL DEFAULT '', -- community, pro, enterprise
  status TEXT NOT NULL DEFAULT '', -- stripe's own, or trial
  customer_id TEXT NOT NULL DEFAULT '', -- stripe customer id, opaque
  subscription_id TEXT NOT NULL DEFAULT '', -- stripe subscription id, opaque
  current_period_end TIMESTAMPTZ,
  cancel_at_period_end BOOLEAN NOT NULL DEFAULT FALSE,
  seats BIGINT NOT NULL DEFAULT 0, -- paid quantity, 0 = the plan's own cap
  ended_at TIMESTAMPTZ, -- set once the subscription is over, starts the retention hold
  trial_reminder INTEGER NOT NULL DEFAULT 0, -- days before the trial end of the last reminder sent, 0 for none
  deletion_warning INTEGER NOT NULL DEFAULT 0, -- days before the deletion of the last warning sent, 0 for none
  deletion_warned_at TIMESTAMPTZ, -- when it went out, a late warning pushes the deletion back
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  email TEXT NOT NULL CHECK (email = lower(email)),
  name TEXT NOT NULL DEFAULT '',
  picture TEXT,
  role INTEGER NOT NULL DEFAULT 1 CHECK (role BETWEEN 1 AND 5), -- 1=member, 2=viewer, 3=editor, 4=admin, 5=owner
  active BOOLEAN NOT NULL DEFAULT TRUE,
  scim_external_id TEXT, -- the identity provider's id for an account SCIM provisions
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, email),
  UNIQUE (workspace_id, id),
  UNIQUE (workspace_id, scim_external_id)
);

CREATE UNIQUE INDEX idx_users_owner ON users (workspace_id)
WHERE
  role = 5;

CREATE TABLE credentials (
  id TEXT PRIMARY KEY, -- webauthn credential id or uuidv7
  workspace_id UUID NOT NULL DEFAULT current_workspace_id (),
  user_id UUID NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('passkey', 'oidc')),
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

CREATE TABLE one_time_tokens (
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

CREATE TABLE known_devices (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  user_id UUID NOT NULL,
  -- The hash of a browser's device cookie, or the DPoP key thumbprint of a terminal.
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

CREATE TABLE sso_providers (
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  provider_id TEXT NOT NULL CHECK (provider_id ~ '^[a-z0-9-]{1,64}$'),
  name TEXT NOT NULL DEFAULT '',
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  config BYTEA NOT NULL DEFAULT '', -- encrypted
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (workspace_id, provider_id)
);

CREATE TABLE service_accounts (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  name TEXT NOT NULL, -- e.g. "github-actions-deploy", "ansible-prod"
  description TEXT,
  role INTEGER NOT NULL DEFAULT 1 CHECK (role BETWEEN 1 AND 3), -- like users.role, the editor at most
  last_used_at TIMESTAMPTZ, -- of any of its tokens, kept by note_service_account_used
  tags TEXT[] NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, name),
  UNIQUE (workspace_id, id)
);

-- Everything that authenticates a call. Every row is a credential, what only remembers a device is in known_devices.
CREATE TABLE access_tokens (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  token_hash TEXT NOT NULL UNIQUE,
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('user', 'cli', 'daemon', 'service_account', 'scim')),
  -- One subject column per kind, none for scim. No foreign key, a daemon's token outlives it for the REJECTED answer.
  user_id UUID,
  service_account_id UUID,
  daemon_id UUID,
  subject_id UUID GENERATED ALWAYS AS (COALESCE(user_id, service_account_id, daemon_id)) STORED,
  method TEXT NOT NULL, -- passkey, magic_link, oidc, device, token, scim
  binding TEXT NOT NULL DEFAULT '', -- DPoP JWK thumbprint, empty for cookie sessions and keys
  label TEXT NOT NULL DEFAULT '', -- the name the new sign-in mail gives a terminal, or the key's label
  ip TEXT NOT NULL DEFAULT '', -- of the request that created the token
  user_agent TEXT NOT NULL DEFAULT '', -- of the request that created the token
  expires_at TIMESTAMPTZ, -- NULL never expires (daemons re-auth via DPoP proofs, until expire_daemon_token)
  last_seen_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  FOREIGN KEY (workspace_id, user_id) REFERENCES users (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, service_account_id) REFERENCES service_accounts (workspace_id, id) ON DELETE CASCADE,
  -- A kind is one value, so these three also keep it to one subject, and to none for scim.
  CHECK ((kind IN ('user', 'cli')) = (user_id IS NOT NULL)),
  CHECK ((kind = 'daemon') = (daemon_id IS NOT NULL)),
  CHECK ((kind = 'service_account') = (service_account_id IS NOT NULL))
);

CREATE INDEX idx_access_tokens_subject ON access_tokens (subject_id);

CREATE INDEX idx_access_tokens_workspace ON access_tokens (workspace_id);

CREATE INDEX idx_access_tokens_expiry ON access_tokens (expires_at)
WHERE
  expires_at IS NOT NULL;

-- The account remembers when any of its tokens was last used, so a list of accounts needs no join.
CREATE FUNCTION note_service_account_used () RETURNS TRIGGER AS $$
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

CREATE TABLE teams (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  tags TEXT[] NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, id)
);

CREATE TABLE team_members (
  workspace_id UUID NOT NULL DEFAULT current_workspace_id (),
  user_id UUID NOT NULL,
  team_id UUID NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (user_id, team_id),
  FOREIGN KEY (workspace_id, user_id) REFERENCES users (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, team_id) REFERENCES teams (workspace_id, id) ON DELETE CASCADE
);

CREATE TABLE ssh_cas (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  private_key BYTEA NOT NULL, -- encrypted
  public_key TEXT NOT NULL, -- OpenSSH wire format
  previous_public_key TEXT, -- the key before the last rollover
  previous_trusted_until TIMESTAMPTZ, -- its certificates are trusted until then
  not_before TIMESTAMPTZ NOT NULL,
  not_after TIMESTAMPTZ NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  is_default BOOLEAN NOT NULL DEFAULT FALSE,
  key_type INTEGER NOT NULL, -- 1=rsa, 2=ecdsa, 3=ed25519
  key_bits INTEGER NOT NULL,
  -- The settings below have no defaults here. ssh.NewCA holds the one set a new CA starts with.
  lifetime INTERVAL NOT NULL, -- of the next key, a rollover reads it
  user_default_ttl INTERVAL NOT NULL,
  user_max_ttl INTERVAL NOT NULL,
  force_command TEXT NOT NULL DEFAULT '', -- runs instead of what the user asks for
  source_address TEXT NOT NULL DEFAULT '', -- addresses and CIDRs a login may come from, comma separated
  host_default_ttl INTERVAL NOT NULL,
  host_max_ttl INTERVAL NOT NULL,
  allowed_key_types INTEGER[] NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, name),
  UNIQUE (workspace_id, id),
  CHECK (not_before < not_after),
  CHECK (user_default_ttl <= user_max_ttl),
  CHECK (host_default_ttl <= host_max_ttl)
);

-- Enroll tokens bring daemons in, invite tokens bring people in. The plaintext is "<id>_<secret>".
CREATE TABLE join_tokens (
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
  tags TEXT[] NOT NULL DEFAULT '{}', -- enroll only
  retire_after INTERVAL, -- enroll only, set on an ephemeral token
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at TIMESTAMPTZ,
  UNIQUE (workspace_id, id),
  FOREIGN KEY (workspace_id, ca_id) REFERENCES ssh_cas (workspace_id, id) ON DELETE SET NULL (ca_id),
  CHECK (
    kind = 1
    OR (
      NOT auto_approve
      AND ca_id IS NULL
      AND tags = '{}'
      AND retire_after IS NULL
    )
  ),
  CHECK ((kind = 2) = (role IS NOT NULL))
);

CREATE TABLE daemons (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  status INTEGER NOT NULL DEFAULT 1 CHECK (status IN (1, 2, 3)), -- 1=pending, 2=accepted, 3=rejected
  -- Refreshed by the instance holding the control stream. Online means seen in the last 30 seconds.
  last_seen_at TIMESTAMPTZ,
  key_thumbprint TEXT,
  config JSONB NOT NULL DEFAULT '{}',
  metadata JSONB NOT NULL DEFAULT '{}',
  -- The enroll token that made it, kept so a replacement of the same name is only ever its own.
  join_token_id UUID,
  -- Set from an ephemeral token. The sweep deletes the daemon this long after it was last seen.
  retire_after INTERVAL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, name),
  UNIQUE (workspace_id, id),
  UNIQUE (workspace_id, key_thumbprint),
  FOREIGN KEY (workspace_id, join_token_id) REFERENCES join_tokens (workspace_id, id) ON DELETE SET NULL (join_token_id)
)
-- Every connected daemon is stamped every ten seconds. Half-empty pages let the new row version stay on its page,
-- so the stamp never touches an index.
WITH
  (fillfactor = 50);

CREATE TABLE targets (
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
  last_sync_at TIMESTAMPTZ, -- when a host without a daemon last ran nk sync
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, name),
  UNIQUE (workspace_id, id),
  FOREIGN KEY (workspace_id, ca_id) REFERENCES ssh_cas (workspace_id, id) ON DELETE SET NULL (ca_id),
  FOREIGN KEY (workspace_id, daemon_id) REFERENCES daemons (workspace_id, id) ON DELETE CASCADE
);

-- A local account on a target, like root or deploy. Grants hang off it.
CREATE TABLE target_accounts (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  target_id UUID NOT NULL,
  username TEXT NOT NULL, -- e.g. "root", "ubuntu", "ec2-user"
  -- When the host first reported it. NULL is an account an admin or a token added that the host has not shown yet.
  seen_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (target_id, username),
  UNIQUE (workspace_id, id),
  FOREIGN KEY (workspace_id, target_id) REFERENCES targets (workspace_id, id) ON DELETE CASCADE
);

-- Exactly one subject column is set. Every reference is workspace-scoped and cascades, so no grant is left behind.
CREATE TABLE grants (
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
  -- NULL is for good. Resolvers skip a grant past it at once, the expiry job deletes it within a minute.
  expires_at TIMESTAMPTZ,
  FOREIGN KEY (workspace_id, account_id) REFERENCES target_accounts (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, user_id) REFERENCES users (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, team_id) REFERENCES teams (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, service_account_id) REFERENCES service_accounts (workspace_id, id) ON DELETE CASCADE,
  PRIMARY KEY (account_id, subject_id),
  CHECK (num_nonnulls (user_id, team_id, service_account_id) = 1)
);

-- The grants that have not ended. Every resolver reads this, so an ended grant opens nothing even before the expiry
-- job deletes it. security_invoker keeps the row security of the caller.
CREATE VIEW live_grants
WITH
  (security_invoker = TRUE) AS
SELECT
  *
FROM
  grants
WHERE
  expires_at IS NULL
  OR expires_at > NOW();

-- The grants an enroll token seeds on every target it makes. Same shape as grants, keyed by token and username.
CREATE TABLE join_token_grants (
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  token_id UUID NOT NULL,
  username TEXT NOT NULL,
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
  FOREIGN KEY (workspace_id, token_id) REFERENCES join_tokens (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, user_id) REFERENCES users (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, team_id) REFERENCES teams (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, service_account_id) REFERENCES service_accounts (workspace_id, id) ON DELETE CASCADE,
  PRIMARY KEY (token_id, username, subject_id),
  CHECK (num_nonnulls (user_id, team_id, service_account_id) = 1)
);

-- A member asks for an account for a while and an admin decides. Approving grants it until then. A request nobody
-- answers expires after a day.
CREATE TABLE access_requests (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  requester_id UUID NOT NULL,
  account_id UUID NOT NULL,
  duration INTERVAL NOT NULL,
  reason TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (
    status IN ('pending', 'approved', 'denied', 'cancelled', 'expired')
  ),
  decided_by UUID,
  decided_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  FOREIGN KEY (workspace_id, requester_id) REFERENCES users (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, account_id) REFERENCES target_accounts (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, decided_by) REFERENCES users (workspace_id, id) ON DELETE SET NULL (decided_by)
);

-- One open request per person and account.
CREATE UNIQUE INDEX idx_access_requests_pending ON access_requests (requester_id, account_id)
WHERE
  status = 'pending';

CREATE INDEX idx_access_requests_workspace ON access_requests (workspace_id, created_at DESC);

CREATE INDEX idx_access_requests_requester ON access_requests (requester_id, created_at DESC);

-- A request with the names it is shown with.
CREATE VIEW access_request_details
WITH
  (security_invoker = TRUE) AS
SELECT
  r.*,
  t.id AS target_id,
  t.name AS target_name,
  p.username,
  u.name AS requester_name,
  u.email AS requester_email,
  COALESCE(d.name, d.email, '') AS decider_name
FROM
  access_requests r
  JOIN target_accounts p ON p.id = r.account_id
  JOIN targets t ON t.id = p.target_id
  JOIN users u ON u.id = r.requester_id
  LEFT JOIN users d ON d.id = r.decided_by;

-- Where audit events go as they happen, like a SIEM. The cursor is the last event sent, so nothing is dropped and
-- events go in order. A retry may send one again, its id tells. A failing stream is retried after retry_at.
CREATE TABLE audit_streams (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('webhook', 'splunk', 'datadog')),
  url TEXT NOT NULL,
  secret BYTEA NOT NULL, -- the HMAC key, HEC token or API key, stored encrypted
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  cursor_ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  cursor_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
  last_sent_at TIMESTAMPTZ,
  last_error TEXT NOT NULL DEFAULT '',
  failing_since TIMESTAMPTZ,
  retry_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_streams_workspace ON audit_streams (workspace_id);

-- When a subject last got a certificate for a target, for the access review. nk signs again once half of a
-- certificate's life is gone, so this trails real use by a few days at most. A row of a deleted subject is ignored.
CREATE TABLE access_usage (
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  target_id UUID NOT NULL,
  subject_id UUID NOT NULL,
  last_cert_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (target_id, subject_id),
  FOREIGN KEY (workspace_id, target_id) REFERENCES targets (workspace_id, id) ON DELETE CASCADE
);

CREATE TABLE recordings (
  id UUID PRIMARY KEY DEFAULT uuidv7(), -- the session id
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  daemon_id UUID,
  daemon_name TEXT NOT NULL, -- as it was when the session ran
  username TEXT NOT NULL,
  -- Who was logged in, parsed out of the principal the host matched. NULL from a daemon that did not say.
  subject_id UUID,
  subject_name TEXT NOT NULL DEFAULT '', -- its email, or the name of a service account, when the session ran
  principal TEXT NOT NULL DEFAULT '',
  key BYTEA NOT NULL, -- encrypts this recording's frames, stored encrypted
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ended_at TIMESTAMPTZ,
  size_bytes BIGINT NOT NULL DEFAULT 0,
  complete BOOLEAN NOT NULL DEFAULT FALSE, -- False when upload stream ended abruptly
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  FOREIGN KEY (workspace_id, daemon_id) REFERENCES daemons (workspace_id, id) ON DELETE SET NULL (daemon_id)
);

-- Keeps the audit rows and recordings of a time range past their retention, for an incident or an investigation.
-- Not the billing hold, which keeps the data of an ended plan for a while. ends_at NULL holds until released.
CREATE TABLE legal_holds (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  reason TEXT NOT NULL,
  starts_at TIMESTAMPTZ NOT NULL,
  ends_at TIMESTAMPTZ,
  created_by UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (
    ends_at IS NULL
    OR ends_at > starts_at
  ),
  FOREIGN KEY (workspace_id, created_by) REFERENCES users (workspace_id, id) ON DELETE SET NULL (created_by)
);

CREATE INDEX idx_legal_holds_workspace ON legal_holds (workspace_id);

-- Whether a legal hold keeps what a workspace recorded at stamp. Every delete of audit rows and recordings asks it.
CREATE FUNCTION legal_hold_covers (ws UUID, stamp TIMESTAMPTZ) RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
  SELECT EXISTS (
    SELECT 1 FROM legal_holds h
    WHERE h.workspace_id = ws AND stamp >= h.starts_at AND (h.ends_at IS NULL OR stamp < h.ends_at)
  )
$$;

-- The one keyset that encrypts everything at rest. rotated_at is when it last got a new primary key.
CREATE TABLE keysets (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  data BYTEA NOT NULL,
  rotated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- License key activated in the UI (singleton)
CREATE TABLE instance_license (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  key TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The CA of the built-in TLS (singleton)
CREATE TABLE web_ca (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  private_key BYTEA NOT NULL,
  certificate BYTEA NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes --------------------------------------------------------------------
-- A search or a tag filter reads the rows of one workspace and filters them. An index on the name or the tags
-- of every workspace is never picked for that, so there is none. The rows of one workspace are found through its
-- UNIQUE (workspace_id, id), which also returns them in id order.

-- SCIM expects displayName to resolve to one group per workspace (RFC 7643), or member updates hit the wrong team.
CREATE UNIQUE INDEX idx_teams_workspace_name ON teams (workspace_id, name);

CREATE INDEX idx_team_members_team_id ON team_members (team_id);

-- One default per workspace. SetDefaultCA moves it in one statement.
CREATE UNIQUE INDEX idx_ssh_cas_default ON ssh_cas (workspace_id)
WHERE
  is_default = TRUE;

CREATE INDEX idx_targets_ca_id ON targets (ca_id);

-- A daemon serves one target, a manual target has none.
CREATE UNIQUE INDEX idx_targets_daemon_id ON targets (daemon_id);

CREATE INDEX idx_join_tokens_workspace ON join_tokens (workspace_id, kind);

CREATE INDEX idx_grants_subject ON grants (subject_id);

CREATE INDEX idx_grants_workspace_id ON grants (workspace_id);

CREATE INDEX idx_grants_expires_at ON grants (expires_at)
WHERE
  expires_at IS NOT NULL;

-- Carries the size, so the storage total of a workspace is read from the index alone.
CREATE INDEX idx_recordings_workspace_started ON recordings (workspace_id, started_at DESC) INCLUDE (size_bytes);

CREATE INDEX idx_recordings_subject ON recordings (workspace_id, subject_id, started_at DESC);

-- The list of one daemon's sessions, and the foreign key: without it a deleted daemon scans every recording.
CREATE INDEX idx_recordings_daemon ON recordings (daemon_id, started_at DESC);

-- Triggers -------------------------------------------------------------------
-- Any change to what a daemon enforces bumps the workspace version and notifies on commit.
CREATE FUNCTION create_workspace_state () RETURNS TRIGGER AS $$
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

CREATE FUNCTION bump_state_version () RETURNS TRIGGER AS $$
DECLARE
  ws UUID;
BEGIN
  IF TG_TABLE_NAME = 'workspaces' THEN
    ws := NEW.id;
  ELSIF TG_OP = 'DELETE' THEN
    ws := OLD.workspace_id;
  ELSE
    ws := NEW.workspace_id;
  END IF;
  -- Once per transaction. A team with thousands of grants would otherwise rewrite the row for each of them.
  IF current_setting('nokku.bumped', TRUE) = ws::TEXT THEN
    RETURN NULL;
  END IF;
  UPDATE workspace_state SET version = version + 1 WHERE workspace_id = ws;
  PERFORM pg_notify('nokku_state', ws::TEXT);
  PERFORM set_config('nokku.bumped', ws::TEXT, TRUE);
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

-- An expiry moved earlier must reach the hosts before the old one would have.
CREATE TRIGGER bump_state_version_update
AFTER
UPDATE OF expires_at ON grants FOR EACH ROW WHEN (OLD.expires_at IS DISTINCT FROM NEW.expires_at)
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

-- Daemons take the idle timeout from the workspace settings, nothing else in them.
CREATE TRIGGER bump_state_version
AFTER
UPDATE OF settings ON workspaces FOR EACH ROW WHEN (
  OLD.settings -> 'session_idle_timeout' IS DISTINCT FROM NEW.settings -> 'session_idle_timeout'
)
EXECUTE FUNCTION bump_state_version ();

-- A deactivated account must leave every daemon's map at once.
CREATE TRIGGER bump_state_version
AFTER
UPDATE OF active ON users FOR EACH ROW WHEN (OLD.active IS DISTINCT FROM NEW.active)
EXECUTE FUNCTION bump_state_version ();

-- A deleted daemon's token stays for the REJECTED answer of its next sync. A host that is gone never asks, so the
-- token expires a day after the longest certificate that host could still trust.
CREATE FUNCTION expire_daemon_token () RETURNS TRIGGER AS $$
BEGIN
  UPDATE access_tokens
  SET expires_at = NOW() + INTERVAL '366 days'
  WHERE subject_id = OLD.id AND kind = 'daemon';
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER expire_daemon_token
AFTER DELETE ON daemons FOR EACH ROW
EXECUTE FUNCTION expire_daemon_token ();

-- Console hints. A change is announced on commit as "<workspace id>:<table>", once per transaction, with no data.
CREATE FUNCTION notify_change () RETURNS TRIGGER AS $$
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

-- Sign-ins are left out, no list shows them to others. Keys and SCIM tokens are, see the triggers after the loop.
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
    'join_token_grants',
    'service_accounts',
    'daemons',
    'teams',
    'team_members',
    'ssh_cas',
    'targets',
    'target_accounts',
    'grants',
    'recordings',
    'legal_holds',
    'access_requests',
    'audit_streams'
  ] LOOP
    EXECUTE format(
      'CREATE TRIGGER notify_change AFTER INSERT OR DELETE ON %I
         FOR EACH ROW EXECUTE FUNCTION notify_change ()',
      t
    );
    -- Stamps move on a timer or with every use, nobody waits for them. Every other column is named, so a
    -- statement that only stamps does not fire this. One that names a stamp and another column does.
    EXECUTE format(
      'CREATE TRIGGER notify_change_update AFTER UPDATE OF %s ON %I
         FOR EACH ROW WHEN (OLD IS DISTINCT FROM NEW)
         EXECUTE FUNCTION notify_change ()',
      (
        SELECT
          string_agg(quote_ident(attname), ', ' ORDER BY attnum)
        FROM
          pg_attribute
        WHERE
          attrelid = t::REGCLASS
          AND attnum > 0
          AND NOT attisdropped
          AND attgenerated = ''
          AND attname NOT IN ('last_seen_at', 'last_used_at', 'last_sync_at', 'cursor_ts', 'cursor_id', 'last_sent_at')
      ),
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

-- A gap wider than the online window means this stamp brings the daemon online. Going offline is no write.
CREATE TRIGGER notify_online
AFTER
UPDATE OF last_seen_at ON daemons FOR EACH ROW WHEN (
  OLD.last_seen_at IS NULL
  OR NEW.last_seen_at - OLD.last_seen_at > INTERVAL '30 seconds'
)
EXECUTE FUNCTION notify_change ();

-- Roles and grants -----------------------------------------------------------
-- nokku_app serves requests under RLS, nokku_system bypasses it. Neither is a member of the other.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nokku_app') THEN
    CREATE ROLE nokku_app NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nokku_system') THEN
    CREATE ROLE nokku_system NOLOGIN BYPASSRLS;
  END IF;
END $$;

GRANT USAGE ON SCHEMA public TO nokku_app,
nokku_system;

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
-- One policy on every tenant table, the only tenant filter there is. A new table needs its name in the list below.
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
    'join_token_grants',
    'service_accounts',
    'daemons',
    'teams',
    'team_members',
    'ssh_cas',
    'targets',
    'target_accounts',
    'grants',
    'access_usage',
    'recordings',
    'legal_holds',
    'access_requests',
    'audit_streams'
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
CREATE SCHEMA audit;

-- One row per thing that happened. workspace_id has no foreign key, the log outlives a deleted workspace.
CREATE TABLE audit.audit_logs (
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

CREATE INDEX idx_audit_logs_workspace_time ON audit.audit_logs (workspace_id, timestamp DESC);

CREATE INDEX idx_audit_logs_actor ON audit.audit_logs (workspace_id, actor_id, timestamp DESC);

-- For the retention delete. Rows arrive in time order, so a block range index stays tiny.
CREATE INDEX idx_audit_logs_time ON audit.audit_logs USING brin (timestamp);

CREATE POLICY tenant_isolation ON audit.audit_logs FOR
SELECT
  TO nokku_app USING (workspace_id = current_workspace_id ());

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
-- No role holds UPDATE, and this trigger refuses a DELETE unless the transaction opts in, as the retention job does.
CREATE FUNCTION audit.audit_logs_immutable () RETURNS trigger LANGUAGE plpgsql AS $$
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
