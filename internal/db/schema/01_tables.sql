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
  kind TEXT NOT NULL DEFAULT 'cli', -- 'cli' | 'web'
  token_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '6 months'),
  last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS oauth_identities (
  provider_id TEXT NOT NULL, -- ID from the OAuth provider
  provider TEXT NOT NULL, -- 'google', 'github', 'oidc' etc.
  user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  provider_email TEXT, -- email from provider (can be different from user email)
  provider_username TEXT, -- username from provider
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (provider_id, provider)
);

CREATE TABLE IF NOT EXISTS passkeys (
  id TEXT PRIMARY KEY, -- base64-encoded credential ID
  user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  name TEXT, -- e.g. "IPhone 13"
  public_key BYTEA NOT NULL,
  attestation_type TEXT NOT NULL, -- e.g. "none", "basic", "self"
  aaguid BYTEA, -- authenticator's unique ID
  sign_count BIGINT NOT NULL DEFAULT 0, -- protects against cloned authenticators
  transports TEXT[], -- ["usb", "ble", "nfc", "internal"]
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

CREATE TABLE IF NOT EXISTS roles (
  name TEXT PRIMARY KEY,
  description TEXT NOT NULL DEFAULT '',
  permissions TEXT[] NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS workspaces (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  name TEXT NOT NULL,
  description TEXT,
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

CREATE TABLE IF NOT EXISTS workspace_settings (
  workspace_id UUID PRIMARY KEY REFERENCES workspaces (id) ON DELETE CASCADE,
  enroll_token_hash TEXT,
  enroll_expires_at TIMESTAMPTZ,
  enroll_auto_approve BOOLEAN NOT NULL DEFAULT TRUE,
  invite_token_hash TEXT,
  invite_expires_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
  token_hash TEXT,
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

-- Keysets (for envelope encryption - singleton)
CREATE TABLE IF NOT EXISTS keysets (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  data BYTEA NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
