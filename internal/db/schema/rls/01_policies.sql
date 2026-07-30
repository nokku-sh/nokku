-- Helper function to get current workspace IDs from session
CREATE OR REPLACE FUNCTION current_workspace_ids () RETURNS UUID[] AS $$
DECLARE
  ids_text TEXT;
BEGIN
  ids_text := current_setting('nokku.workspace_ids', true);
  IF ids_text IS NULL OR ids_text = '' THEN
    RETURN ARRAY[]::UUID[];
  END IF;
  RETURN string_to_array(ids_text, ',')::UUID[];
END;
$$ LANGUAGE plpgsql STABLE;

-- Get current actor type: 'user', 'service_account', or 'daemon'
CREATE OR REPLACE FUNCTION current_actor_type () RETURNS TEXT AS $$
BEGIN
  RETURN COALESCE(current_setting('nokku.actor_type', true), 'user');
END;
$$ LANGUAGE plpgsql STABLE;

-- Single permission check 
CREATE OR REPLACE FUNCTION has_permission (ws_id UUID, perm_code TEXT) RETURNS BOOLEAN AS $$
DECLARE
  actor_type TEXT;
  user_id_text TEXT;
BEGIN
  -- Always require workspace context membership first.
  IF NOT (ws_id = ANY (current_workspace_ids ())) THEN
    RETURN FALSE;
  END IF;

  actor_type := current_actor_type ();

  -- Service accounts can manage operational workspace resources,
  -- but cannot change critical control-plane settings.
  IF actor_type = 'service_account' THEN
    RETURN perm_code NOT IN (
      'workspace.edit',
      'workspace.delete',
      'members.edit',
      'settings.edit',
      'domains.edit',
      'sso.edit'
    );
  END IF;

  -- Daemons are limited to daemon/target/principal operations.
  IF actor_type = 'daemon' THEN
    RETURN perm_code IN (
      'daemons.view',
      'daemons.edit',
      'targets.view',
      'targets.edit',
      'principals.view',
      'principals.edit',
      'cas.view'
    );
  END IF;

  user_id_text := current_setting('nokku.user_id', true);
  IF user_id_text IS NULL OR user_id_text = '' THEN
    RETURN FALSE;
  END IF;

  RETURN EXISTS (
    SELECT 1
    FROM workspace_members wm
    JOIN roles r ON r.name = wm.role_name
    WHERE wm.workspace_id = ws_id
      AND wm.user_id = user_id_text::UUID
      AND perm_code = ANY(r.permissions)
  );
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER
SET
  search_path = public,
  pg_catalog;

-- Enable RLS on workspace-scoped tables
ALTER TABLE workspaces ENABLE ROW LEVEL SECURITY;

ALTER TABLE workspace_members ENABLE ROW LEVEL SECURITY;

ALTER TABLE workspace_domains ENABLE ROW LEVEL SECURITY;

ALTER TABLE workspace_settings ENABLE ROW LEVEL SECURITY;

ALTER TABLE oidc_providers ENABLE ROW LEVEL SECURITY;

ALTER TABLE saml_providers ENABLE ROW LEVEL SECURITY;

ALTER TABLE service_accounts ENABLE ROW LEVEL SECURITY;

ALTER TABLE teams ENABLE ROW LEVEL SECURITY;

ALTER TABLE team_members ENABLE ROW LEVEL SECURITY;

ALTER TABLE certificate_authorities ENABLE ROW LEVEL SECURITY;

ALTER TABLE targets ENABLE ROW LEVEL SECURITY;

ALTER TABLE principals ENABLE ROW LEVEL SECURITY;

ALTER TABLE principal_users ENABLE ROW LEVEL SECURITY;

ALTER TABLE principal_teams ENABLE ROW LEVEL SECURITY;

ALTER TABLE principal_service_accounts ENABLE ROW LEVEL SECURITY;

ALTER TABLE daemons ENABLE ROW LEVEL SECURITY;

-- ============================================
-- WORKSPACES
-- ============================================
CREATE POLICY workspace_insert ON workspaces FOR INSERT TO nokku_app
WITH
  CHECK (
    current_actor_type () = 'user'
    AND COALESCE(current_setting('nokku.user_id', TRUE), '') <> ''
  );

CREATE POLICY workspace_select ON workspaces FOR
SELECT
  TO nokku_app USING (id = ANY (current_workspace_ids ()));

CREATE POLICY workspace_update ON workspaces
FOR UPDATE
  TO nokku_app USING (
    id = ANY (current_workspace_ids ())
    AND has_permission (id, 'workspace.edit')
  )
WITH
  CHECK (
    id = ANY (current_workspace_ids ())
    AND has_permission (id, 'workspace.edit')
  );

CREATE POLICY workspace_delete ON workspaces FOR DELETE TO nokku_app USING (
  id = ANY (current_workspace_ids ())
  AND has_permission (id, 'workspace.delete')
);

-- ============================================
-- WORKSPACE MEMBERS
-- ============================================
CREATE POLICY workspace_members_select ON workspace_members FOR
SELECT
  TO nokku_app USING (
    workspace_id = ANY (current_workspace_ids ())
    AND has_permission (workspace_id, 'members.view')
  );

CREATE POLICY workspace_members_insert ON workspace_members FOR INSERT TO nokku_app
WITH
  CHECK (
    (
      workspace_id = ANY (current_workspace_ids ())
      AND has_permission (workspace_id, 'members.edit')
    )
    OR (
      current_actor_type () = 'user'
      AND EXISTS (
        SELECT
          1
        FROM
          workspaces w
        WHERE
          w.id = workspace_id
          AND w.created_by = current_setting('nokku.user_id', TRUE)::UUID
      )
    )
  );

CREATE POLICY workspace_members_update ON workspace_members
FOR UPDATE
  TO nokku_app USING (
    workspace_id = ANY (current_workspace_ids ())
    AND has_permission (workspace_id, 'members.edit')
  )
WITH
  CHECK (
    workspace_id = ANY (current_workspace_ids ())
    AND has_permission (workspace_id, 'members.edit')
  );

CREATE POLICY workspace_members_delete ON workspace_members FOR DELETE TO nokku_app USING (
  workspace_id = ANY (current_workspace_ids ())
  AND (
    has_permission (workspace_id, 'members.edit')
    OR (
      current_actor_type () = 'user'
      AND user_id = current_setting('nokku.user_id', TRUE)::UUID
    )
  )
);

-- ============================================
-- OWNER-ONLY TABLES (pattern: view + edit)
-- ============================================
-- Workspace Settings
CREATE POLICY workspace_settings_select ON workspace_settings FOR
SELECT
  TO nokku_app USING (
    workspace_id = ANY (current_workspace_ids ())
    AND has_permission (workspace_id, 'settings.view')
  );

CREATE POLICY workspace_settings_insert ON workspace_settings FOR INSERT TO nokku_app
WITH
  CHECK (
    current_actor_type () = 'user'
    AND EXISTS (
      SELECT
        1
      FROM
        workspaces w
      WHERE
        w.id = workspace_id
        AND w.created_by = current_setting('nokku.user_id', TRUE)::UUID
    )
  );

CREATE POLICY workspace_settings_mutate ON workspace_settings FOR ALL TO nokku_app USING (
  workspace_id = ANY (current_workspace_ids ())
  AND has_permission (workspace_id, 'settings.edit')
)
WITH
  CHECK (
    workspace_id = ANY (current_workspace_ids ())
    AND has_permission (workspace_id, 'settings.edit')
  );

-- Workspace Domains
CREATE POLICY workspace_domains_select ON workspace_domains FOR
SELECT
  TO nokku_app USING (
    workspace_id = ANY (current_workspace_ids ())
    AND has_permission (workspace_id, 'domains.view')
  );

CREATE POLICY workspace_domains_mutate ON workspace_domains FOR ALL TO nokku_app USING (
  workspace_id = ANY (current_workspace_ids ())
  AND has_permission (workspace_id, 'domains.edit')
)
WITH
  CHECK (
    workspace_id = ANY (current_workspace_ids ())
    AND has_permission (workspace_id, 'domains.edit')
  );

-- OIDC Providers
CREATE POLICY oidc_providers_select ON oidc_providers FOR
SELECT
  TO nokku_app USING (
    workspace_id = ANY (current_workspace_ids ())
    AND has_permission (workspace_id, 'sso.view')
  );

CREATE POLICY oidc_providers_mutate ON oidc_providers FOR ALL TO nokku_app USING (
  workspace_id = ANY (current_workspace_ids ())
  AND has_permission (workspace_id, 'sso.edit')
)
WITH
  CHECK (
    workspace_id = ANY (current_workspace_ids ())
    AND has_permission (workspace_id, 'sso.edit')
  );

-- SAML Providers
CREATE POLICY saml_providers_select ON saml_providers FOR
SELECT
  TO nokku_app USING (
    workspace_id = ANY (current_workspace_ids ())
    AND has_permission (workspace_id, 'sso.view')
  );

CREATE POLICY saml_providers_mutate ON saml_providers FOR ALL TO nokku_app USING (
  workspace_id = ANY (current_workspace_ids ())
  AND has_permission (workspace_id, 'sso.edit')
)
WITH
  CHECK (
    workspace_id = ANY (current_workspace_ids ())
    AND has_permission (workspace_id, 'sso.edit')
  );

-- Certificate Authorities
CREATE POLICY cas_select ON certificate_authorities FOR
SELECT
  TO nokku_app USING (
    workspace_id = ANY (current_workspace_ids ())
    AND has_permission (workspace_id, 'cas.view')
  );

CREATE POLICY cas_mutate ON certificate_authorities FOR ALL TO nokku_app USING (
  workspace_id = ANY (current_workspace_ids ())
  AND has_permission (workspace_id, 'cas.edit')
)
WITH
  CHECK (
    workspace_id = ANY (current_workspace_ids ())
    AND has_permission (workspace_id, 'cas.edit')
  );

-- ============================================
-- ADMIN TABLES 
-- ============================================
-- Targets
CREATE POLICY targets_select ON targets FOR
SELECT
  TO nokku_app USING (
    workspace_id = ANY (current_workspace_ids ())
    AND has_permission (workspace_id, 'targets.view')
  );

CREATE POLICY targets_mutate ON targets FOR ALL TO nokku_app USING (
  workspace_id = ANY (current_workspace_ids ())
  AND has_permission (workspace_id, 'targets.edit')
)
WITH
  CHECK (
    workspace_id = ANY (current_workspace_ids ())
    AND has_permission (workspace_id, 'targets.edit')
  );

-- Daemons
CREATE POLICY daemons_select ON daemons FOR
SELECT
  TO nokku_app USING (
    workspace_id = ANY (current_workspace_ids ())
    AND has_permission (workspace_id, 'daemons.view')
  );

CREATE POLICY daemons_mutate ON daemons FOR ALL TO nokku_app USING (
  workspace_id = ANY (current_workspace_ids ())
  AND has_permission (workspace_id, 'daemons.edit')
)
WITH
  CHECK (
    workspace_id = ANY (current_workspace_ids ())
    AND has_permission (workspace_id, 'daemons.edit')
  );

-- Teams
CREATE POLICY teams_select ON teams FOR
SELECT
  TO nokku_app USING (
    workspace_id = ANY (current_workspace_ids ())
    AND has_permission (workspace_id, 'teams.view')
  );

CREATE POLICY teams_mutate ON teams FOR ALL TO nokku_app USING (
  workspace_id = ANY (current_workspace_ids ())
  AND has_permission (workspace_id, 'teams.edit')
)
WITH
  CHECK (
    workspace_id = ANY (current_workspace_ids ())
    AND has_permission (workspace_id, 'teams.edit')
  );

-- Team Members
CREATE POLICY team_members_select ON team_members FOR
SELECT
  TO nokku_app USING (
    workspace_id = ANY (current_workspace_ids ())
    AND has_permission (workspace_id, 'teams.view')
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

CREATE POLICY team_members_mutate ON team_members FOR ALL TO nokku_app USING (
  workspace_id = ANY (current_workspace_ids ())
  AND has_permission (workspace_id, 'teams.edit')
  AND EXISTS (
    SELECT
      1
    FROM
      teams t
    WHERE
      t.id = team_id
      AND t.workspace_id = team_members.workspace_id
  )
)
WITH
  CHECK (
    workspace_id = ANY (current_workspace_ids ())
    AND has_permission (workspace_id, 'teams.edit')
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

-- Service Accounts
CREATE POLICY service_accounts_select ON service_accounts FOR
SELECT
  TO nokku_app USING (
    workspace_id = ANY (current_workspace_ids ())
    AND has_permission (workspace_id, 'service_accounts.view')
  );

CREATE POLICY service_accounts_mutate ON service_accounts FOR ALL TO nokku_app USING (
  workspace_id = ANY (current_workspace_ids ())
  AND has_permission (workspace_id, 'service_accounts.edit')
)
WITH
  CHECK (
    workspace_id = ANY (current_workspace_ids ())
    AND has_permission (workspace_id, 'service_accounts.edit')
  );

-- ============================================
-- PRINCIPALS
-- ============================================
CREATE POLICY principals_select ON principals FOR
SELECT
  TO nokku_app USING (
    workspace_id = ANY (current_workspace_ids ())
    AND has_permission (workspace_id, 'principals.view')
  );

CREATE POLICY principals_mutate ON principals FOR ALL TO nokku_app USING (
  workspace_id = ANY (current_workspace_ids ())
  AND has_permission (workspace_id, 'principals.edit')
)
WITH
  CHECK (
    workspace_id = ANY (current_workspace_ids ())
    AND has_permission (workspace_id, 'principals.edit')
  );

-- Principal Users 
CREATE POLICY principal_users_select ON principal_users FOR
SELECT
  TO nokku_app USING (
    workspace_id = ANY (current_workspace_ids ())
    AND has_permission (workspace_id, 'principals.view')
  );

CREATE POLICY principal_users_mutate ON principal_users FOR ALL TO nokku_app USING (
  workspace_id = ANY (current_workspace_ids ())
  AND has_permission (workspace_id, 'principals.edit')
)
WITH
  CHECK (
    workspace_id = ANY (current_workspace_ids ())
    AND has_permission (workspace_id, 'principals.edit')
  );

-- Principal Teams
CREATE POLICY principal_teams_select ON principal_teams FOR
SELECT
  TO nokku_app USING (
    workspace_id = ANY (current_workspace_ids ())
    AND has_permission (workspace_id, 'principals.view')
  );

CREATE POLICY principal_teams_mutate ON principal_teams FOR ALL TO nokku_app USING (
  workspace_id = ANY (current_workspace_ids ())
  AND has_permission (workspace_id, 'principals.edit')
)
WITH
  CHECK (
    workspace_id = ANY (current_workspace_ids ())
    AND has_permission (workspace_id, 'principals.edit')
  );

-- Principal Service Accounts
CREATE POLICY principal_service_accounts_select ON principal_service_accounts FOR
SELECT
  TO nokku_app USING (
    workspace_id = ANY (current_workspace_ids ())
    AND has_permission (workspace_id, 'principals.view')
  );

CREATE POLICY principal_service_accounts_mutate ON principal_service_accounts FOR ALL TO nokku_app USING (
  workspace_id = ANY (current_workspace_ids ())
  AND has_permission (workspace_id, 'principals.edit')
)
WITH
  CHECK (
    workspace_id = ANY (current_workspace_ids ())
    AND has_permission (workspace_id, 'principals.edit')
  );
