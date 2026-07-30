-- Foreign key indexes (required for efficient CASCADE deletes and JOINs)
CREATE INDEX idx_oauth_identities_user_id ON oauth_identities (user_id);

CREATE INDEX idx_oauth_identities_provider_email ON oauth_identities (provider_email);

CREATE INDEX idx_user_devices_user_id ON user_devices (user_id);

CREATE INDEX idx_passkeys_user_id ON passkeys (user_id);

CREATE INDEX idx_backup_codes_user_id ON backup_codes (user_id);

CREATE INDEX idx_workspaces_created_by ON workspaces (created_by);

CREATE INDEX idx_workspace_members_user_id ON workspace_members (user_id, workspace_id);

CREATE INDEX idx_workspace_domains_workspace_id ON workspace_domains (workspace_id);

CREATE INDEX idx_workspace_domains_domain ON workspace_domains (domain);

CREATE INDEX idx_workspace_domains_verified ON workspace_domains (workspace_id, verified_at)
WHERE
  verified_at IS NOT NULL;

CREATE INDEX idx_oidc_providers_active ON oidc_providers (workspace_id)
WHERE
  is_active = TRUE;

CREATE INDEX idx_service_accounts_workspace_id ON service_accounts (workspace_id);

CREATE INDEX idx_service_accounts_workspace_id_id ON service_accounts (workspace_id, id);

CREATE INDEX idx_service_accounts_name_trgm ON service_accounts USING GIN (name gin_trgm_ops);

CREATE INDEX idx_service_accounts_description_trgm ON service_accounts USING GIN (description gin_trgm_ops);

CREATE INDEX idx_service_accounts_tags ON service_accounts USING GIN (tags);

CREATE INDEX idx_daemons_workspace_id ON daemons (workspace_id);

CREATE INDEX idx_daemons_workspace_id_id ON daemons (workspace_id, id);

CREATE INDEX idx_daemons_name_trgm ON daemons USING GIN (name gin_trgm_ops);

CREATE INDEX idx_teams_workspace_id ON teams (workspace_id);

CREATE INDEX idx_teams_workspace_id_id ON teams (workspace_id, id);

CREATE INDEX idx_teams_name_trgm ON teams USING GIN (name gin_trgm_ops);

CREATE INDEX idx_teams_description_trgm ON teams USING GIN (description gin_trgm_ops);

CREATE INDEX idx_teams_tags ON teams USING GIN (tags);

CREATE INDEX idx_team_members_team_id ON team_members (team_id);

CREATE INDEX idx_ca_workspace_id ON certificate_authorities (workspace_id);

CREATE INDEX idx_ca_workspace_id_id ON certificate_authorities (workspace_id, id);

CREATE INDEX idx_ca_name_trgm ON certificate_authorities USING GIN (name gin_trgm_ops);

CREATE UNIQUE INDEX idx_ca_default_per_workspace ON certificate_authorities (workspace_id)
WHERE
  is_default = TRUE;

CREATE INDEX idx_targets_workspace_id ON targets (workspace_id);

CREATE INDEX idx_targets_ca_id ON targets (ca_id);

CREATE INDEX idx_targets_daemon_id ON targets (daemon_id);

CREATE INDEX idx_targets_tags ON targets USING GIN (tags);

CREATE INDEX idx_targets_workspace_id_id ON targets (workspace_id, id);

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

-- User email lookup (for SSO domain matching and login)
CREATE INDEX idx_users_email ON users (email);

CREATE INDEX idx_users_name_trgm ON users USING GIN (name gin_trgm_ops);

CREATE INDEX idx_users_username_trgm ON users USING GIN (username gin_trgm_ops);

CREATE INDEX idx_users_email_trgm ON users USING GIN (email gin_trgm_ops);
