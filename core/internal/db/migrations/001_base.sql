CREATE DOMAIN hashed_token AS TEXT;

CREATE DOMAIN sealed AS BYTEA;

CREATE FUNCTION current_workspace_id () RETURNS UUID AS $$
  SELECT NULLIF(current_setting('nokku.workspace_id', TRUE), '')::UUID
$$ LANGUAGE sql STABLE;

CREATE TABLE workspaces (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  slug TEXT NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  settings JSONB NOT NULL DEFAULT '{}',
  requestable_tags TEXT[] NOT NULL DEFAULT '{}',
  claimed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE workspace_licenses (
  workspace_id UUID PRIMARY KEY DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  key TEXT NOT NULL DEFAULT '',
  license_id TEXT UNIQUE,
  ends_at TIMESTAMPTZ,
  trial_reminder_days INTEGER NOT NULL DEFAULT 0,
  deletion_warning_days INTEGER NOT NULL DEFAULT 0,
  deletion_warned_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (
    key <> ''
    OR ends_at IS NOT NULL
  )
);

CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  email TEXT NOT NULL CHECK (email = lower(email)),
  name TEXT NOT NULL DEFAULT '',
  picture TEXT NOT NULL DEFAULT '',
  role INTEGER NOT NULL DEFAULT 1 CHECK (role > 0), -- 1=member, 2=viewer, 3=editor, 4=admin, 5=owner
  active BOOLEAN NOT NULL DEFAULT TRUE,
  CHECK (
    role <> 5
    OR active
  ),
  scim_external_id TEXT,
  scim_managed BOOLEAN NOT NULL DEFAULT FALSE,
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

CREATE INDEX idx_users_email ON users (email);

CREATE TABLE teams (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  tags TEXT[] NOT NULL DEFAULT '{}',
  scim_external_id TEXT,
  scim_managed BOOLEAN NOT NULL DEFAULT FALSE,
  scim_adoptable BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, id),
  UNIQUE (workspace_id, scim_external_id)
);

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
  description TEXT NOT NULL DEFAULT '',
  role INTEGER NOT NULL DEFAULT 1 CHECK (role BETWEEN 1 AND 3),
  tags TEXT[] NOT NULL DEFAULT '{}',
  force_command TEXT NOT NULL DEFAULT '',
  source_address TEXT NOT NULL DEFAULT '',
  last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, name),
  UNIQUE (workspace_id, id)
);

CREATE TABLE service_account_federations (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  service_account_id UUID NOT NULL,
  issuer TEXT NOT NULL CHECK (issuer <> ''),
  claims JSONB NOT NULL CHECK (
    jsonb_typeof(claims) = 'object'
    AND claims <> '{}'
  ),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  FOREIGN KEY (workspace_id, service_account_id) REFERENCES service_accounts (workspace_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_service_account_federations_account ON service_account_federations (service_account_id);

CREATE TABLE sso_providers (
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  provider_id TEXT NOT NULL CHECK (provider_id ~ '^[a-z0-9-]{1,64}$'),
  name TEXT NOT NULL DEFAULT '',
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  config sealed NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (workspace_id, provider_id)
);

CREATE TABLE passkeys (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id (),
  user_id UUID NOT NULL,
  credential_id TEXT NOT NULL,
  data BYTEA NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, credential_id),
  FOREIGN KEY (workspace_id, user_id) REFERENCES users (workspace_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_passkeys_user ON passkeys (user_id);

CREATE TABLE oidc_identities (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id (),
  user_id UUID NOT NULL,
  provider_id TEXT NOT NULL,
  subject TEXT NOT NULL CHECK (subject <> ''),
  last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, provider_id, subject),
  UNIQUE (workspace_id, user_id, provider_id),
  FOREIGN KEY (workspace_id, user_id) REFERENCES users (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, provider_id) REFERENCES sso_providers (workspace_id, provider_id) ON DELETE CASCADE
);

CREATE TABLE known_devices (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  user_id UUID NOT NULL,
  key TEXT NOT NULL,
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
  token_hash hashed_token PRIMARY KEY,
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  user_id UUID NOT NULL,
  purpose TEXT NOT NULL CHECK (purpose IN ('login', 'email_change', 'email_revert')),
  email TEXT NOT NULL DEFAULT '' CHECK (email = lower(email)),
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK ((purpose = 'login') = (email = '')),
  FOREIGN KEY (workspace_id, user_id) REFERENCES users (workspace_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_one_time_tokens_expiry ON one_time_tokens (expires_at);

CREATE INDEX idx_one_time_tokens_user ON one_time_tokens (user_id, purpose);

CREATE TABLE invites (
  token_hash hashed_token PRIMARY KEY,
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  email TEXT NOT NULL CHECK (email = lower(email)),
  role INTEGER NOT NULL CHECK (role BETWEEN 1 AND 4),
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, email)
);

CREATE INDEX idx_invites_expiry ON invites (expires_at);

CREATE TABLE device_grants (
  device_code_hash hashed_token PRIMARY KEY,
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  user_code TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied')),
  decided_by UUID,
  approved_method TEXT NOT NULL DEFAULT '' CHECK (approved_method IN ('', 'passkey', 'magic_link', 'oidc', 'device', 'token', 'federation', 'scim')),
  ip TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT '',
  polled_at TIMESTAMPTZ,
  early_polls INTEGER NOT NULL DEFAULT 0,
  loopback_port INTEGER CHECK (loopback_port BETWEEN 1024 AND 65535),
  loopback_code_hash hashed_token UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, user_code),
  CHECK (
    loopback_code_hash IS NULL
    OR loopback_port IS NOT NULL
  ),
  CHECK ((status = 'pending') = (decided_by IS NULL)),
  CHECK (
    status <> 'approved'
    OR approved_method <> ''
  ),
  FOREIGN KEY (workspace_id, decided_by) REFERENCES users (workspace_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_device_grants_expiry ON device_grants (expires_at);

CREATE TABLE access_tokens (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  token_hash hashed_token NOT NULL UNIQUE,
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('user', 'cli', 'daemon', 'service_account', 'scim')),
  user_id UUID,
  service_account_id UUID,
  -- No foreign key, a deleted daemon's token still hears that it was removed.
  daemon_id UUID,
  subject_id UUID GENERATED ALWAYS AS (COALESCE(user_id, service_account_id, daemon_id)) STORED,
  method TEXT NOT NULL CHECK (method IN ('passkey', 'magic_link', 'oidc', 'device', 'token', 'federation', 'scim')),
  dpop_thumbprint TEXT NOT NULL DEFAULT '',
  ssh_key TEXT NOT NULL DEFAULT '',
  label TEXT NOT NULL DEFAULT '',
  ip TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT '',
  expires_at TIMESTAMPTZ,
  last_seen_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  FOREIGN KEY (workspace_id, user_id) REFERENCES users (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, service_account_id) REFERENCES service_accounts (workspace_id, id) ON DELETE CASCADE,
  CHECK ((kind IN ('user', 'cli')) = (user_id IS NOT NULL)),
  CHECK ((kind = 'daemon') = (daemon_id IS NOT NULL)),
  CHECK ((kind = 'service_account') = (service_account_id IS NOT NULL)),
  CHECK ((kind = 'cli') = (ssh_key <> '')),
  CHECK (
    kind <> 'service_account'
    OR expires_at IS NOT NULL
  ),
  CHECK (
    method <> 'federation'
    OR (
      kind = 'service_account'
      AND dpop_thumbprint <> ''
    )
  )
);

CREATE INDEX idx_access_tokens_subject ON access_tokens (subject_id);

CREATE INDEX idx_access_tokens_workspace ON access_tokens (workspace_id);

CREATE INDEX idx_access_tokens_expiry ON access_tokens (expires_at)
WHERE
  expires_at IS NOT NULL;

CREATE TABLE spent_job_tokens (
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  issuer TEXT NOT NULL,
  jti TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (workspace_id, issuer, jti)
);

CREATE INDEX idx_spent_job_tokens_expiry ON spent_job_tokens (expires_at);

CREATE TABLE ssh_cas (
  workspace_id UUID PRIMARY KEY DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  user_public_key TEXT NOT NULL,
  host_public_key TEXT NOT NULL,
  rotated_at TIMESTAMPTZ,
  user_ttl INTERVAL NOT NULL,
  source_address TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE ssh_ca_keys (
  workspace_id UUID PRIMARY KEY DEFAULT current_workspace_id () REFERENCES ssh_cas (workspace_id) ON DELETE CASCADE,
  user_private_key sealed NOT NULL,
  host_private_key sealed NOT NULL
);

CREATE TABLE join_tokens (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  token_hash hashed_token NOT NULL UNIQUE,
  label TEXT NOT NULL DEFAULT '',
  tags TEXT[] NOT NULL DEFAULT '{}',
  auto_approve BOOLEAN NOT NULL DEFAULT FALSE,
  retire_after INTERVAL CHECK (retire_after > INTERVAL '0'),
  max_uses INTEGER CHECK (max_uses > 0),
  uses INTEGER NOT NULL DEFAULT 0 CHECK (uses <= max_uses),
  expires_at TIMESTAMPTZ,
  last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, id)
);

CREATE TABLE targets (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  endpoints TEXT[] NOT NULL DEFAULT '{}',
  host_public_key TEXT NOT NULL DEFAULT '',
  tags TEXT[] NOT NULL DEFAULT '{}',
  metadata JSONB NOT NULL DEFAULT '{}',
  manual_sync_at TIMESTAMPTZ,
  created_by UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, id)
);

CREATE UNIQUE INDEX idx_targets_name ON targets (workspace_id, lower(name));

CREATE INDEX idx_targets_tags ON targets USING gin (tags);

CREATE TABLE daemons (
  target_id UUID PRIMARY KEY,
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  join_token_id UUID,
  key_thumbprint TEXT NOT NULL,
  version TEXT NOT NULL DEFAULT '',
  accepted BOOLEAN NOT NULL DEFAULT FALSE,
  config JSONB NOT NULL DEFAULT '{}',
  retire_after INTERVAL,
  last_seen_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, target_id),
  UNIQUE (workspace_id, key_thumbprint),
  FOREIGN KEY (workspace_id, target_id) REFERENCES targets (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, join_token_id) REFERENCES join_tokens (workspace_id, id) ON DELETE SET NULL (join_token_id)
);

CREATE TABLE target_accounts (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  target_id UUID NOT NULL,
  username TEXT NOT NULL,
  first_seen_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (target_id, username),
  UNIQUE (workspace_id, id),
  FOREIGN KEY (workspace_id, target_id) REFERENCES targets (workspace_id, id) ON DELETE CASCADE
);

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
  expires_at TIMESTAMPTZ,
  FOREIGN KEY (workspace_id, account_id) REFERENCES target_accounts (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, user_id) REFERENCES users (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, team_id) REFERENCES teams (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, service_account_id) REFERENCES service_accounts (workspace_id, id) ON DELETE CASCADE,
  PRIMARY KEY (account_id, subject_id),
  CHECK (num_nonnulls (user_id, team_id, service_account_id) = 1)
);

CREATE INDEX idx_grants_subject ON grants (subject_id);

CREATE INDEX idx_grants_workspace_expires_at ON grants (workspace_id, expires_at);

CREATE INDEX idx_grants_expires_at ON grants (expires_at)
WHERE
  expires_at IS NOT NULL;

CREATE INDEX idx_grants_team_id ON grants (team_id)
WHERE
  team_id IS NOT NULL;

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

CREATE TABLE access_requests (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  requester_id UUID NOT NULL,
  account_id UUID NOT NULL,
  duration INTERVAL NOT NULL CHECK (duration > INTERVAL '0'),
  reason TEXT NOT NULL,
  -- AccessRequestStatus: 1=pending, 2=approved, 3=denied, 4=cancelled, 5=expired
  status INTEGER NOT NULL DEFAULT 1 CHECK (status > 0),
  decided_by UUID,
  decided_at TIMESTAMPTZ,
  decision_reason TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK ((status IN (2, 3)) = (decided_at IS NOT NULL)),
  FOREIGN KEY (workspace_id, requester_id) REFERENCES users (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, account_id) REFERENCES target_accounts (workspace_id, id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, decided_by) REFERENCES users (workspace_id, id) ON DELETE SET NULL (decided_by)
);

CREATE UNIQUE INDEX idx_access_requests_pending ON access_requests (requester_id, account_id)
WHERE
  status = 1;

CREATE INDEX idx_access_requests_workspace ON access_requests (workspace_id, created_at DESC);

CREATE INDEX idx_access_requests_requester ON access_requests (requester_id, created_at DESC);

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
  COALESCE(d.accepted, TRUE) AS daemon_ok
FROM
  live_grants g
  JOIN target_accounts p ON p.workspace_id = g.workspace_id
  AND p.id = g.account_id
  LEFT JOIN daemons d ON d.workspace_id = p.workspace_id
  AND d.target_id = p.target_id
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
  COALESCE(d.accepted, TRUE)
FROM
  live_grants g
  JOIN team_members m ON m.workspace_id = g.workspace_id
  AND m.team_id = g.team_id
  JOIN users u ON u.workspace_id = m.workspace_id
  AND u.id = m.user_id
  JOIN target_accounts p ON p.workspace_id = g.workspace_id
  AND p.id = g.account_id
  LEFT JOIN daemons d ON d.workspace_id = p.workspace_id
  AND d.target_id = p.target_id;

CREATE VIEW access_request_details
WITH
  (security_invoker = TRUE) AS
SELECT
  t.id AS target_id,
  t.name AS target_name,
  p.username,
  u.name AS requester_name,
  u.email AS requester_email,
  COALESCE(d.name, d.email, '') AS decider_name,
  r.*
FROM
  access_requests r
  JOIN target_accounts p ON p.id = r.account_id
  JOIN targets t ON t.id = p.target_id
  JOIN users u ON u.id = r.requester_id
  LEFT JOIN users d ON d.id = r.decided_by;

CREATE TABLE access_usage (
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  target_id UUID NOT NULL,
  subject_id UUID NOT NULL,
  last_cert_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (target_id, subject_id),
  FOREIGN KEY (workspace_id, target_id) REFERENCES targets (workspace_id, id) ON DELETE CASCADE
);

CREATE TABLE recordings (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  daemon_id UUID,
  daemon_name TEXT NOT NULL,
  username TEXT NOT NULL,
  subject_id UUID,
  subject_name TEXT NOT NULL DEFAULT '',
  principal TEXT NOT NULL DEFAULT '',
  key sealed NOT NULL,
  object_id UUID,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ended_at TIMESTAMPTZ,
  size_bytes BIGINT NOT NULL DEFAULT 0 CHECK (size_bytes >= 0),
  complete BOOLEAN NOT NULL DEFAULT FALSE,
  CHECK (
    NOT complete
    OR object_id IS NOT NULL
  ),
  CHECK (ended_at >= started_at),
  FOREIGN KEY (workspace_id, daemon_id) REFERENCES daemons (workspace_id, target_id) ON DELETE SET NULL (daemon_id)
);

CREATE INDEX idx_recordings_workspace_started ON recordings (workspace_id, started_at DESC) INCLUDE (size_bytes);

CREATE INDEX idx_recordings_subject ON recordings (workspace_id, subject_id, started_at DESC);

CREATE INDEX idx_recordings_daemon ON recordings (daemon_id, started_at DESC);

CREATE TABLE recording_deletes (
  object_id UUID PRIMARY KEY,
  workspace_id UUID NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  next_try_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_recording_deletes_due ON recording_deletes (next_try_at);

CREATE TABLE audit_streams (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  workspace_id UUID NOT NULL DEFAULT current_workspace_id () REFERENCES workspaces (id) ON DELETE CASCADE,
  kind INTEGER NOT NULL CHECK (kind > 0), -- AuditStreamKind: 1=webhook, 2=splunk, 3=datadog
  url TEXT NOT NULL,
  secret sealed NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  cursor_ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  cursor_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
  last_sent_at TIMESTAMPTZ,
  last_error TEXT NOT NULL DEFAULT '',
  failing_since TIMESTAMPTZ,
  failure_mailed_at TIMESTAMPTZ,
  retry_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_streams_workspace ON audit_streams (workspace_id);

CREATE TABLE keysets (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  data BYTEA NOT NULL,
  rotated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

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

-- A day after the longest certificate that host could still trust.
CREATE FUNCTION expire_daemon_token () RETURNS TRIGGER AS $$
BEGIN
  UPDATE access_tokens
  SET expires_at = NOW() + INTERVAL '366 days'
  WHERE subject_id = OLD.target_id AND kind = 'daemon';
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER expire_daemon_token
AFTER DELETE ON daemons FOR EACH ROW
EXECUTE FUNCTION expire_daemon_token ();

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

CREATE FUNCTION queue_lost_recording_object (lost UUID) RETURNS VOID AS $$
  INSERT INTO recording_deletes (workspace_id, object_id) VALUES (current_workspace_id (), lost)
  ON CONFLICT (object_id) DO NOTHING;
$$ LANGUAGE sql SECURITY DEFINER
SET
  search_path = public,
  pg_temp;

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

CREATE TRIGGER notify_state_change
AFTER
UPDATE OF settings ON workspaces FOR EACH ROW WHEN (
  OLD.settings -> 'session_idle_timeout' IS DISTINCT FROM NEW.settings -> 'session_idle_timeout'
)
EXECUTE FUNCTION notify_state_change ();

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
UPDATE OF user_public_key,
host_public_key ON ssh_cas FOR EACH ROW WHEN (
  OLD.user_public_key IS DISTINCT FROM NEW.user_public_key
  OR OLD.host_public_key IS DISTINCT FROM NEW.host_public_key
)
EXECUTE FUNCTION notify_state_change ();

CREATE TRIGGER notify_state_change
AFTER
UPDATE OF accepted,
config ON daemons FOR EACH ROW WHEN (
  OLD.accepted IS DISTINCT FROM NEW.accepted
  OR OLD.config IS DISTINCT FROM NEW.config
)
EXECUTE FUNCTION notify_state_change ();

CREATE TRIGGER notify_state_change_delete
AFTER DELETE ON daemons FOR EACH ROW
EXECUTE FUNCTION notify_state_change ();

CREATE TRIGGER notify_state_change
AFTER DELETE ON target_accounts FOR EACH ROW
EXECUTE FUNCTION notify_state_change ();

CREATE TRIGGER notify_state_change
AFTER INSERT
OR DELETE ON grants FOR EACH ROW
EXECUTE FUNCTION notify_state_change ();

CREATE TRIGGER notify_state_change_update
AFTER
UPDATE OF expires_at ON grants FOR EACH ROW WHEN (OLD.expires_at IS DISTINCT FROM NEW.expires_at)
EXECUTE FUNCTION notify_state_change ();

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nokku_app') THEN
    CREATE ROLE nokku_app NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nokku_system') THEN
    CREATE ROLE nokku_system NOLOGIN BYPASSRLS;
  END IF;
END $$;

GRANT nokku_app,
nokku_system TO CURRENT_USER;

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

REVOKE ALL ON recording_deletes
FROM
  nokku_app;

REVOKE INSERT ON recording_deletes
FROM
  nokku_system;

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
    'passkeys',
    'oidc_identities',
    'known_devices',
    'one_time_tokens',
    'invites',
    'device_grants',
    'access_tokens',
    'spent_job_tokens',
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

CREATE SCHEMA audit;

CREATE TABLE audit.audit_logs (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  -- Not NOW(), so the rows of one transaction keep the order they were written in.
  timestamp TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  -- No foreign key, the log outlives a deleted workspace.
  workspace_id UUID NOT NULL,
  actor_id TEXT NOT NULL DEFAULT '',
  actor_kind TEXT NOT NULL DEFAULT '',
  actor_name TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '',
  ok BOOLEAN NOT NULL,
  ip TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT '',
  details JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_audit_logs_workspace_time ON audit.audit_logs (workspace_id, timestamp DESC);

CREATE INDEX idx_audit_logs_actor ON audit.audit_logs (workspace_id, actor_id, timestamp DESC);

CREATE INDEX idx_audit_logs_target ON audit.audit_logs (workspace_id, target, timestamp DESC);

CREATE INDEX idx_audit_logs_time ON audit.audit_logs USING brin (timestamp);

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

GRANT
SELECT
,
  INSERT ON ALL TABLES IN SCHEMA audit TO nokku_app;

GRANT
SELECT
,
  DELETE ON ALL TABLES IN SCHEMA audit TO nokku_system;

-- tern made its version table before this file ran, so the grants above reached it.
REVOKE ALL ON public.schema_version
FROM
  nokku_app,
  nokku_system;
