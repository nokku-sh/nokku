-- Every tenant table carries workspace_id and its foreign keys include it, so no row points into another workspace.
-- Searches and tag filters scan one workspace's rows, found through UNIQUE (workspace_id, id), so names and tags
-- have no index of their own.
-- Tenancy --------------------------------------------------------------------
CREATE FUNCTION current_workspace_id () RETURNS UUID AS $$
  SELECT NULLIF(current_setting('nokku.workspace_id', TRUE), '')::UUID
$$ LANGUAGE sql STABLE;

CREATE TABLE workspaces (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  slug TEXT NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
  name TEXT NOT NULL,
  description TEXT,
  settings JSONB NOT NULL DEFAULT '{}',
  requestable_tags TEXT[] NOT NULL DEFAULT '{}',
  claimed_at TIMESTAMPTZ, -- the first sign-in, NULL is a signup nobody used
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The license key of a workspace. Hosted signup starts a trial row without a key, self-hosted has none until a key.
CREATE TABLE workspace_licenses (
  workspace_id UUID PRIMARY KEY DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  key TEXT NOT NULL DEFAULT '', -- empty during a hosted trial, kept once expired for the retention hold
  license_id TEXT UNIQUE, -- the id signed into the key, so one license unlocks one workspace
  ends_at TIMESTAMPTZ, -- the trial end until a key, then the key's expiry. NULL for a key that never expires
  trial_reminder INTEGER NOT NULL DEFAULT 0, -- days before the trial end of the last reminder, 0 for none
  deletion_warning INTEGER NOT NULL DEFAULT 0, -- days before the deletion of the last warning, 0 for none
  deletion_warned_at TIMESTAMPTZ, -- a late warning pushes the deletion back
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (
    key <> ''
    OR ends_at IS NOT NULL
  )
);

-- Subjects -------------------------------------------------------------------
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  email TEXT NOT NULL CHECK (email = lower(email)),
  name TEXT NOT NULL DEFAULT '',
  picture TEXT,
  role INTEGER NOT NULL DEFAULT 1 CHECK (role BETWEEN 1 AND 5), -- 1=member, 2=viewer, 3=editor, 4=admin, 5=owner
  active BOOLEAN NOT NULL DEFAULT TRUE,
  CHECK (
    role <> 5
    OR active
  ), -- the owner can't be switched off
  scim_external_id TEXT,
  scim_managed BOOLEAN NOT NULL DEFAULT FALSE, -- SCIM created it, so the identity provider owns the address
  -- SCIM switched it off, so SCIM may switch it on again. What an admin switched off stays off until an admin says so.
  scim_deactivated BOOLEAN NOT NULL DEFAULT FALSE CHECK (NOT (scim_deactivated AND active)),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, email),
  UNIQUE (workspace_id, id),
  UNIQUE (workspace_id, scim_external_id)
);

CREATE UNIQUE INDEX idx_users_owner ON users (workspace_id)
WHERE
  role = 5;

CREATE TABLE teams (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  tags TEXT[] NOT NULL DEFAULT '{}',
  scim_external_id TEXT,
  -- SCIM only sees teams it made or took over. An IdP that syncs deletes every group it does not know.
  scim_managed BOOLEAN NOT NULL DEFAULT FALSE,
  -- An admin lets a SCIM group of the same name take this team over, with its grants. Used up by the takeover.
  scim_open BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, id),
  UNIQUE (workspace_id, scim_external_id)
);

-- SCIM resolves a displayName to one group per workspace (RFC 7643).
CREATE UNIQUE INDEX idx_teams_workspace_name ON teams (workspace_id, name);

CREATE TABLE team_members (
  workspace_id UUID NOT NULL DEFAULT current_workspace_id (),
  user_id UUID NOT NULL,
  team_id UUID NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (user_id, team_id),
  FOREIGN KEY (workspace_id, user_id) REFERENCES users (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, team_id) REFERENCES teams (workspace_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_team_members_team_id ON team_members (team_id);

CREATE TABLE service_accounts (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  role INTEGER NOT NULL DEFAULT 1 CHECK (role BETWEEN 1 AND 3), -- like users.role, the editor at most
  tags TEXT[] NOT NULL DEFAULT '{}',
  force_command TEXT NOT NULL DEFAULT '', -- what its certificates run, whatever the login asks for
  source_address TEXT NOT NULL DEFAULT '', -- addresses and CIDRs, comma separated
  last_used_at TIMESTAMPTZ, -- kept by note_service_account_used
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, name),
  UNIQUE (workspace_id, id)
);

-- Which CI jobs may sign in as a service account: the issuer of their token and the claims it must hold.
CREATE TABLE service_account_federations (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  service_account_id UUID NOT NULL,
  issuer TEXT NOT NULL CHECK (issuer <> ''),
  claims JSONB NOT NULL CHECK (
    jsonb_typeof(claims) = 'object'
    AND claims <> '{}'
  ), -- string to string, each must match exactly
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  FOREIGN KEY (workspace_id, service_account_id) REFERENCES service_accounts (workspace_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_service_account_federations_account ON service_account_federations (service_account_id);

-- Sign-in --------------------------------------------------------------------
CREATE TABLE sso_providers (
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  provider_id TEXT NOT NULL CHECK (provider_id ~ '^[a-z0-9-]{1,64}$'),
  name TEXT NOT NULL DEFAULT '',
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  config BYTEA NOT NULL, -- the OIDC settings as JSON, sealed
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (workspace_id, provider_id)
);

CREATE TABLE credentials (
  id TEXT PRIMARY KEY, -- the webauthn credential id, or a uuidv7
  workspace_id UUID NOT NULL DEFAULT current_workspace_id (),
  user_id UUID NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('passkey', 'oidc')),
  provider TEXT NOT NULL DEFAULT '',
  subject TEXT NOT NULL DEFAULT '',
  data BYTEA NOT NULL DEFAULT '',
  label TEXT NOT NULL DEFAULT '',
  CHECK (
    type <> 'oidc'
    OR (
      provider <> ''
      AND subject <> ''
    )
  ),
  last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  FOREIGN KEY (workspace_id, user_id) REFERENCES users (workspace_id, id) ON DELETE CASCADE
);

-- An external identity links to at most one user of the workspace.
CREATE UNIQUE INDEX idx_credentials_external ON credentials (workspace_id, type, provider, subject)
WHERE
  subject <> '';

-- One identity per provider. A provider may hand a leaver's address to someone new, who must not land on that account.
CREATE UNIQUE INDEX idx_credentials_one_per_provider ON credentials (workspace_id, user_id, provider)
WHERE
  type = 'oidc';

CREATE INDEX idx_credentials_user ON credentials (user_id, type);

CREATE TABLE known_devices (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  user_id UUID NOT NULL,
  key TEXT NOT NULL, -- the hash of a browser's device cookie, or a terminal's DPoP key thumbprint
  ip TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT '',
  expires_at TIMESTAMPTZ NOT NULL,
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, user_id, key),
  FOREIGN KEY (workspace_id, user_id) REFERENCES users (workspace_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_known_devices_expiry ON known_devices (expires_at);

CREATE TABLE one_time_tokens (
  token_hash TEXT PRIMARY KEY,
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  user_id UUID,
  purpose TEXT NOT NULL CHECK (purpose IN ('login', 'invite', 'email_change', 'email_revert')),
  email TEXT CHECK (email = lower(email)),
  role INTEGER CHECK (role BETWEEN 1 AND 4),
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK ((purpose = 'invite') = (user_id IS NULL)),
  CHECK (
    (purpose = 'invite') = (
      role IS NOT NULL
      AND email IS NOT NULL
    )
  ),
  FOREIGN KEY (workspace_id, user_id) REFERENCES users (workspace_id, id) ON DELETE CASCADE
);

-- One pending invite per address, a new one replaces it.
CREATE UNIQUE INDEX idx_one_time_tokens_invite ON one_time_tokens (workspace_id, email)
WHERE
  purpose = 'invite';

CREATE INDEX idx_one_time_tokens_expiry ON one_time_tokens (expires_at);

CREATE INDEX idx_one_time_tokens_user ON one_time_tokens (user_id, purpose);

-- nk login's device flow, waiting until someone approves or denies it in the browser.
CREATE TABLE device_grants (
  device_code_hash TEXT PRIMARY KEY,
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  user_code TEXT NOT NULL, -- a handle, no secret, approving takes a session
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied')),
  user_id UUID, -- who decided
  approved_method TEXT, -- how the approving session signed in, the CLI session inherits it
  ip TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT '',
  polled_at TIMESTAMPTZ,
  violations INTEGER NOT NULL DEFAULT 0, -- polls that came too fast, each widens the interval
  -- nk listens on 127.0.0.1 here. The approval hands the browser a code for it, the token needs that code.
  loopback_port INTEGER CHECK (loopback_port BETWEEN 1024 AND 65535),
  loopback_code_hash TEXT UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, user_code),
  CHECK (
    loopback_code_hash IS NULL
    OR loopback_port IS NOT NULL
  ),
  CHECK ((status = 'pending') = (user_id IS NULL)),
  CHECK (
    status <> 'approved'
    OR approved_method IS NOT NULL
  ),
  FOREIGN KEY (workspace_id, user_id) REFERENCES users (workspace_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_device_grants_expiry ON device_grants (expires_at);

-- Every credential that authenticates a call. known_devices only remembers devices.
CREATE TABLE access_tokens (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  token_hash TEXT NOT NULL UNIQUE,
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('user', 'cli', 'daemon', 'service_account', 'scim')),
  -- One subject column per kind, none for scim. No foreign key on daemon_id, a deleted daemon's token still gets its
  -- REJECTED answer.
  user_id UUID,
  service_account_id UUID,
  daemon_id UUID,
  subject_id UUID GENERATED ALWAYS AS (COALESCE(user_id, service_account_id, daemon_id)) STORED,
  method TEXT NOT NULL, -- passkey, magic_link, oidc, device, token, federation, scim
  binding TEXT NOT NULL DEFAULT '', -- DPoP JWK thumbprint, empty for cookie sessions and keys
  -- The SSH key nk signed in with, the only key the session gets certificates for. Empty for every other kind.
  ssh_key TEXT NOT NULL DEFAULT '',
  label TEXT NOT NULL DEFAULT '',
  ip TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT '',
  expires_at TIMESTAMPTZ, -- NULL never expires, a deleted daemon's gets one from expire_daemon_token
  last_seen_at TIMESTAMPTZ,
  -- Issuer, a space and jti of the job token an exchange spent. The row keeps it spent, so a revoke keeps the row.
  workload_jti TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  FOREIGN KEY (workspace_id, user_id) REFERENCES users (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, service_account_id) REFERENCES service_accounts (workspace_id, id) ON DELETE CASCADE,
  -- A kind is one value, so these three also keep it to one subject.
  CHECK ((kind IN ('user', 'cli')) = (user_id IS NOT NULL)),
  CHECK ((kind = 'daemon') = (daemon_id IS NOT NULL)),
  CHECK ((kind = 'service_account') = (service_account_id IS NOT NULL)),
  CHECK ((kind = 'cli') = (ssh_key <> '')),
  CHECK (
    kind <> 'service_account'
    OR expires_at IS NOT NULL
  ),
  CHECK (
    workload_jti IS NULL
    OR (
      kind = 'service_account'
      AND binding <> ''
    )
  )
);

CREATE INDEX idx_access_tokens_subject ON access_tokens (subject_id);

CREATE INDEX idx_access_tokens_workspace ON access_tokens (workspace_id);

CREATE INDEX idx_access_tokens_expiry ON access_tokens (expires_at)
WHERE
  expires_at IS NOT NULL;

-- A job token works once.
CREATE UNIQUE INDEX idx_access_tokens_workload_jti ON access_tokens (workspace_id, workload_jti)
WHERE
  workload_jti IS NOT NULL;

-- Certificate authorities ----------------------------------------------------
-- One per workspace, made with it. A server has no tie to it, so a rollover reaches every server.
CREATE TABLE ssh_cas (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  -- The user key signs logins, the host key the daemons' host certificates. Private halves are in ssh_ca_keys.
  public_key TEXT NOT NULL,
  host_public_key TEXT NOT NULL,
  rotated_at TIMESTAMPTZ, -- NULL until the first rollover
  -- What a person's certificate lasts, ssh.NewCA holds what a new CA starts with. The ceiling is login.MaxCertTTL.
  user_ttl INTERVAL NOT NULL CHECK (user_ttl BETWEEN INTERVAL '15 minutes' AND INTERVAL '7 days'),
  source_address TEXT NOT NULL DEFAULT '', -- where people log in from, addresses and CIDRs, comma separated
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id),
  UNIQUE (workspace_id, id)
);

-- Apart so reading a CA never touches a private key. Only GetCASigningKey reads one.
CREATE TABLE ssh_ca_keys (
  ca_id UUID NOT NULL,
  workspace_id UUID NOT NULL DEFAULT current_workspace_id (),
  kind TEXT NOT NULL CHECK (kind IN ('user', 'host')),
  private_key BYTEA NOT NULL, -- PKCS#8, sealed
  PRIMARY KEY (ca_id, kind),
  FOREIGN KEY (workspace_id, ca_id) REFERENCES ssh_cas (workspace_id, id) ON DELETE CASCADE
);

-- Servers --------------------------------------------------------------------
-- Enroll tokens bring daemons in. A token is found by its hash, never by its id.
CREATE TABLE join_tokens (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL DEFAULT '',
  tags TEXT[] NOT NULL DEFAULT '{}',
  auto_approve BOOLEAN NOT NULL DEFAULT FALSE,
  retire_after INTERVAL CHECK (retire_after > INTERVAL '0'), -- set on an ephemeral token
  max_uses INTEGER CHECK (max_uses > 0), -- NULL is unlimited
  uses INTEGER NOT NULL DEFAULT 0 CHECK (uses <= max_uses),
  expires_at TIMESTAMPTZ, -- NULL never expires
  last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, id)
);

CREATE INDEX idx_join_tokens_workspace ON join_tokens (workspace_id);

CREATE TABLE daemons (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  join_token_id UUID, -- so a replacement of the same name is only ever its own token's
  key_thumbprint TEXT,
  version TEXT NOT NULL DEFAULT '',
  status INTEGER NOT NULL DEFAULT 1 CHECK (status IN (1, 2, 3)), -- 1=pending, 2=accepted, 3=rejected
  config JSONB NOT NULL DEFAULT '{}',
  retire_after INTERVAL, -- from an ephemeral token, the sweep deletes the daemon this long after it was last seen
  -- Stamped on connect and disconnect. Online is the core's live connection, see daemon.Pool.
  last_seen_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, id),
  UNIQUE (workspace_id, key_thumbprint),
  FOREIGN KEY (workspace_id, join_token_id) REFERENCES join_tokens (workspace_id, id) ON DELETE SET NULL (join_token_id)
);

CREATE TABLE targets (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  daemon_id UUID,
  name TEXT NOT NULL,
  description TEXT,
  endpoints TEXT[],
  host_public_key TEXT,
  tags TEXT[] NOT NULL DEFAULT '{}',
  metadata JSONB NOT NULL DEFAULT '{}',
  last_sync_at TIMESTAMPTZ, -- the last nk sync of a host without a daemon
  -- The person or service account that added the server, NULL after a daemon's enrollment. A service account
  -- may only sync or delete what it added. No foreign key, it is one of two tables and may outlive its row.
  created_by UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, name),
  UNIQUE (workspace_id, id),
  FOREIGN KEY (workspace_id, daemon_id) REFERENCES daemons (workspace_id, id) ON DELETE CASCADE
);

-- A daemon serves one target, a manual target has none. The daemon goes by its target's name.
CREATE UNIQUE INDEX idx_targets_daemon_id ON targets (daemon_id);

-- A local account on a server, like root. Grants point here.
CREATE TABLE target_accounts (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  target_id UUID NOT NULL,
  username TEXT NOT NULL,
  seen_at TIMESTAMPTZ, -- when the host first reported it, NULL while it has not
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (target_id, username),
  UNIQUE (workspace_id, id),
  FOREIGN KEY (workspace_id, target_id) REFERENCES targets (workspace_id, id) ON DELETE CASCADE
);

-- Access ---------------------------------------------------------------------
-- One column per subject kind, so deleting any subject cascades to its grants.
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
  -- NULL is for good. Resolvers skip an ended grant at once, the expiry job deletes it within a minute.
  expires_at TIMESTAMPTZ,
  FOREIGN KEY (workspace_id, account_id) REFERENCES target_accounts (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, user_id) REFERENCES users (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, team_id) REFERENCES teams (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, service_account_id) REFERENCES service_accounts (workspace_id, id) ON DELETE CASCADE,
  PRIMARY KEY (account_id, subject_id),
  CHECK (num_nonnulls (user_id, team_id, service_account_id) = 1)
);

CREATE INDEX idx_grants_subject ON grants (subject_id);

CREATE INDEX idx_grants_workspace_id ON grants (workspace_id);

CREATE INDEX idx_grants_expires_at ON grants (expires_at)
WHERE
  expires_at IS NOT NULL;

CREATE INDEX idx_grants_team_id ON grants (team_id)
WHERE
  team_id IS NOT NULL;

-- The grants an enroll token seeds on every target it makes.
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

-- A request nobody answers expires after a day.
CREATE TABLE access_requests (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  requester_id UUID NOT NULL,
  account_id UUID NOT NULL,
  duration INTERVAL NOT NULL CHECK (duration > INTERVAL '0'),
  reason TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied', 'cancelled', 'expired')),
  decided_by UUID,
  decided_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (
    status NOT IN ('approved', 'denied')
    OR decided_at IS NOT NULL
  ),
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

-- Every resolver reads this, so an ended grant opens nothing even before the expiry job deletes it. security_invoker
-- keeps the caller's row security, on every view here.
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

-- Each live grant as the person or service account it lets in, a team grant once per member. user_ok is false for a
-- deactivated person, daemon_ok for a server whose daemon is not approved. Whatever answers who may log in where reads
-- this and filters or marks with the two.
CREATE VIEW effective_access
WITH
  (security_invoker = TRUE) AS
SELECT
  g.workspace_id,
  p.target_id,
  p.username,
  g.subject_kind,
  g.subject_id,
  NULL::UUID AS team_id,
  g.created_at AS granted_at,
  g.expires_at,
  COALESCE(u.active, TRUE) AS user_ok,
  COALESCE(d.status = 2, TRUE) AS daemon_ok
FROM
  live_grants g
  JOIN target_accounts p ON p.workspace_id = g.workspace_id
  AND p.id = g.account_id
  JOIN targets t ON t.workspace_id = p.workspace_id
  AND t.id = p.target_id
  LEFT JOIN daemons d ON d.workspace_id = t.workspace_id
  AND d.id = t.daemon_id
  LEFT JOIN users u ON u.workspace_id = g.workspace_id
  AND u.id = g.user_id
WHERE
  g.team_id IS NULL
UNION ALL
SELECT
  g.workspace_id,
  p.target_id,
  p.username,
  'user',
  m.user_id,
  g.team_id,
  g.created_at,
  g.expires_at,
  u.active,
  COALESCE(d.status = 2, TRUE)
FROM
  live_grants g
  JOIN team_members m ON m.workspace_id = g.workspace_id
  AND m.team_id = g.team_id
  JOIN users u ON u.workspace_id = m.workspace_id
  AND u.id = m.user_id
  JOIN target_accounts p ON p.workspace_id = g.workspace_id
  AND p.id = g.account_id
  JOIN targets t ON t.workspace_id = p.workspace_id
  AND t.id = p.target_id
  LEFT JOIN daemons d ON d.workspace_id = t.workspace_id
  AND d.id = t.daemon_id;

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

-- Activity -------------------------------------------------------------------
-- When a subject last got a certificate for a target, for the access review. A deleted subject's row is ignored.
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
  subject_id UUID, -- parsed out of the principal the host matched, NULL from a daemon that did not say
  subject_name TEXT NOT NULL DEFAULT '', -- an email or a service account's name, when the session ran
  principal TEXT NOT NULL DEFAULT '',
  key BYTEA NOT NULL, -- sealed
  -- The largest copy stored so far, NULL until there is one. Every upload try writes an object of its own, so a stale
  -- stream can't touch what is stored and a recording made again can't be hit by the delete of the old one.
  object_id UUID,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ended_at TIMESTAMPTZ, -- when the session ended, as the daemon says. A broken upload leaves it NULL
  size_bytes BIGINT NOT NULL DEFAULT 0 CHECK (size_bytes >= 0), -- of the stored copy
  complete BOOLEAN NOT NULL DEFAULT FALSE, -- FALSE when the upload stream ended abruptly
  CHECK (
    NOT complete
    OR object_id IS NOT NULL
  ),
  CHECK (ended_at >= started_at),
  FOREIGN KEY (workspace_id, daemon_id) REFERENCES daemons (workspace_id, id) ON DELETE SET NULL (daemon_id)
);

-- Carries the size, so a workspace's storage total is read from the index alone.
CREATE INDEX idx_recordings_workspace_started ON recordings (workspace_id, started_at DESC) INCLUDE (size_bytes);

CREATE INDEX idx_recordings_subject ON recordings (workspace_id, subject_id, started_at DESC);

-- Also covers the foreign key, a deleted daemon would scan every recording otherwise.
CREATE INDEX idx_recordings_daemon ON recordings (daemon_id, started_at DESC);

-- Objects of deleted recordings for the sweeper to delete. No RLS, only the functions below fill it.
CREATE TABLE recording_deletes (
  object_id UUID PRIMARY KEY,
  workspace_id UUID NOT NULL, -- no reference, the workspace may be gone
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  next_try_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), -- a delete that fails waits again, never holding up the rest
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_recording_deletes_due ON recording_deletes (next_try_at);

-- Where audit events go as they happen. The cursor is the last event sent, so none is dropped and they go in order.
CREATE TABLE audit_streams (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('webhook', 'splunk', 'datadog')),
  url TEXT NOT NULL,
  secret BYTEA NOT NULL, -- the HMAC key, HEC token or API key, sealed
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

-- Instance -------------------------------------------------------------------
-- The one keyset that encrypts everything at rest.
CREATE TABLE keysets (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  data BYTEA NOT NULL,
  rotated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), -- when it last got a new primary key
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Triggers -------------------------------------------------------------------
-- So a list of accounts needs no join, and the time outlives a deleted token.
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

-- Whatever takes an object off a recording, a larger copy or a delete and a cascade from its workspace, leaves it to
-- the sweeper.
CREATE FUNCTION queue_recording_delete () RETURNS TRIGGER AS $$
BEGIN
  IF OLD.object_id IS NOT NULL THEN
    INSERT INTO recording_deletes (workspace_id, object_id) VALUES (OLD.workspace_id, OLD.object_id);
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER
SET
  search_path = public,
  pg_temp;

CREATE TRIGGER queue_recording_delete
AFTER DELETE ON recordings FOR EACH ROW
EXECUTE FUNCTION queue_recording_delete ();

CREATE TRIGGER queue_replaced_recording_object
AFTER
UPDATE OF object_id ON recordings FOR EACH ROW WHEN (OLD.object_id IS DISTINCT FROM NEW.object_id)
EXECUTE FUNCTION queue_recording_delete ();

-- An upload that lost to a larger copy never reached a row, so no trigger sees its object.
CREATE FUNCTION queue_lost_recording_object (lost UUID) RETURNS VOID AS $$
  INSERT INTO recording_deletes (workspace_id, object_id) VALUES (current_workspace_id (), lost);
$$ LANGUAGE sql SECURITY DEFINER
SET
  search_path = public,
  pg_temp;

-- Daemon sync ----------------------------------------------------------------
-- Any change to what a daemon enforces notifies on commit. The core then works out which daemons it touches, see
-- daemon.Pool.Reconcile. Every new input needs a trigger here, or daemons enforce the old state until the next sweep.
CREATE FUNCTION notify_state_change () RETURNS TRIGGER AS $$
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
  -- Once per transaction. A team with thousands of grants would otherwise queue a notification for each of them.
  -- A server coming or going changes nothing for the others, and its own daemon is looked at when it connects.
  IF current_setting('nokku.notified', TRUE) = ws::TEXT OR current_setting('nokku.quiet', TRUE) = 'on' THEN
    RETURN NULL;
  END IF;
  PERFORM pg_notify('nokku_state', ws::TEXT);
  PERFORM set_config('nokku.notified', ws::TEXT, TRUE);
  RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER
SET
  search_path = public,
  pg_temp;

-- Daemons take the idle timeout from the workspace settings, nothing else in them.
CREATE TRIGGER notify_state_change
AFTER
UPDATE OF settings ON workspaces FOR EACH ROW WHEN (
  OLD.settings -> 'session_idle_timeout' IS DISTINCT FROM NEW.settings -> 'session_idle_timeout'
)
EXECUTE FUNCTION notify_state_change ();

-- A deactivated account must leave every daemon's map at once.
CREATE TRIGGER notify_state_change
AFTER
UPDATE OF active ON users FOR EACH ROW WHEN (OLD.active IS DISTINCT FROM NEW.active)
EXECUTE FUNCTION notify_state_change ();

CREATE TRIGGER notify_state_change
AFTER INSERT
OR DELETE ON team_members FOR EACH ROW
EXECUTE FUNCTION notify_state_change ();

CREATE TRIGGER notify_state_change_update
AFTER
UPDATE OF public_key,
host_public_key ON ssh_cas FOR EACH ROW WHEN (
  OLD.public_key IS DISTINCT FROM NEW.public_key
  OR OLD.host_public_key IS DISTINCT FROM NEW.host_public_key
)
EXECUTE FUNCTION notify_state_change ();

CREATE TRIGGER notify_state_change
AFTER
UPDATE OF status,
config ON daemons FOR EACH ROW WHEN (
  OLD.status IS DISTINCT FROM NEW.status
  OR OLD.config IS DISTINCT FROM NEW.config
)
EXECUTE FUNCTION notify_state_change ();

CREATE TRIGGER notify_state_change_delete
AFTER DELETE ON daemons FOR EACH ROW
EXECUTE FUNCTION notify_state_change ();

-- A new account carries no grants, so only deletes matter.
CREATE TRIGGER notify_state_change
AFTER DELETE ON target_accounts FOR EACH ROW
EXECUTE FUNCTION notify_state_change ();

CREATE TRIGGER notify_state_change
AFTER INSERT
OR DELETE ON grants FOR EACH ROW
EXECUTE FUNCTION notify_state_change ();

-- An expiry moved earlier must reach the hosts before the old one would have.
CREATE TRIGGER notify_state_change_update
AFTER
UPDATE OF expires_at ON grants FOR EACH ROW WHEN (OLD.expires_at IS DISTINCT FROM NEW.expires_at)
EXECUTE FUNCTION notify_state_change ();

-- Roles ----------------------------------------------------------------------
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

-- Only those functions queue, the sweeper as nokku_system works the queue off.
REVOKE ALL ON recording_deletes
FROM
  nokku_app;

REVOKE INSERT ON recording_deletes
FROM
  nokku_system;

-- Row-level security ---------------------------------------------------------
-- One policy on every tenant table, the only tenant filter there is. A new table needs its name in this list.
DO $$
DECLARE
  t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'workspace_licenses',
    'users',
    'teams',
    'team_members',
    'service_accounts',
    'service_account_federations',
    'sso_providers',
    'credentials',
    'known_devices',
    'one_time_tokens',
    'device_grants',
    'access_tokens',
    'ssh_cas',
    'ssh_ca_keys',
    'join_tokens',
    'daemons',
    'targets',
    'target_accounts',
    'grants',
    'join_token_grants',
    'access_requests',
    'access_usage',
    'recordings',
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

-- Audit log ------------------------------------------------------------------
CREATE SCHEMA audit;

-- No foreign key on workspace_id, the log outlives a deleted workspace.
CREATE TABLE audit.audit_logs (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  -- The clock and not NOW(), so the rows of one transaction keep the order they were written in.
  timestamp TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  workspace_id UUID NOT NULL,
  actor_id TEXT NOT NULL DEFAULT '',
  actor_kind TEXT NOT NULL DEFAULT '',
  actor_name TEXT NOT NULL DEFAULT '', -- the email or name at the time
  action TEXT NOT NULL, -- an RPC or iam action, like DeleteTarget or Login
  target TEXT NOT NULL DEFAULT '',
  ok BOOLEAN NOT NULL,
  ip TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT '',
  details JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_audit_logs_workspace_time ON audit.audit_logs (workspace_id, timestamp DESC);

CREATE INDEX idx_audit_logs_actor ON audit.audit_logs (workspace_id, actor_id, timestamp DESC);

-- What an event is about. A login is about the person, and its actor is the daemon that reported it.
CREATE INDEX idx_audit_logs_target ON audit.audit_logs (workspace_id, target, timestamp DESC);

-- For the retention delete. Rows arrive in time order, so a block range index stays tiny.
CREATE INDEX idx_audit_logs_time ON audit.audit_logs USING brin (timestamp);

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

ALTER TABLE audit.audit_logs ENABLE ROW LEVEL SECURITY;

ALTER TABLE audit.audit_logs FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON audit.audit_logs FOR
SELECT
  TO nokku_app USING (workspace_id = current_workspace_id ());

CREATE POLICY tenant_insert ON audit.audit_logs FOR INSERT TO nokku_app
WITH
  CHECK (workspace_id = current_workspace_id ());

GRANT USAGE ON SCHEMA audit TO nokku_app,
nokku_system;

-- Every event is written as nokku_app, pinned to its workspace.
GRANT
SELECT
,
  INSERT ON ALL TABLES IN SCHEMA audit TO nokku_app;

-- nokku_system reads every workspace's events for the streams, and deletes for the retention job.
GRANT
SELECT
,
  DELETE ON ALL TABLES IN SCHEMA audit TO nokku_system;

-- tern made its version table before this file ran, so the grants above reached it. Only the owner migrates.
REVOKE ALL ON public.schema_version
FROM
  nokku_app,
  nokku_system;
