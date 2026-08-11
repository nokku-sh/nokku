-- Row-Level Security for nokku
--
-- RLS enforces tenant isolation only. Every workspace-scoped table carries
-- one uniform policy: rows are visible and writable only when the request
-- pinned that workspace in the session GUC "nokku.workspace_id". The GUC is
-- set per transaction by the backend (see internal/db/connection.go).
--
-- Authorization (who may do what) is enforced in Go against the role
-- definitions in internal/db/roles.go. Keep SQL free of permission codes.
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
-- referential integrity checks). internal/db/rls_test.go verifies coverage.
-- Session helpers ------------------------------------------------------------
-- Membership of the current actor in a workspace. Used for cross-tenant
-- reads users legitimately need outside a pinned workspace, mainly listing
-- the workspaces they belong to. Never use this in the workspace_members
-- policy itself (it would recurse)
CREATE OR REPLACE FUNCTION is_workspace_member (ws_id UUID) RETURNS BOOLEAN AS $$
  SELECT EXISTS (
    SELECT 1
    FROM workspace_members wm
    WHERE wm.workspace_id = ws_id
      AND wm.user_id = current_actor_id ()
  )
$$ LANGUAGE sql STABLE;

-- Tables ---------------------------------------------------------------------
ALTER TABLE workspaces ENABLE ROW LEVEL SECURITY;

ALTER TABLE workspaces FORCE ROW LEVEL SECURITY;

ALTER TABLE workspace_members ENABLE ROW LEVEL SECURITY;

ALTER TABLE workspace_members FORCE ROW LEVEL SECURITY;

ALTER TABLE workspace_settings ENABLE ROW LEVEL SECURITY;

ALTER TABLE workspace_settings FORCE ROW LEVEL SECURITY;

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

-- Workspaces -----------------------------------------------------------------
-- Readable when pinned, or when the actor is a member (workspace switcher).
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
-- Members see all rows of the pinned workspace, and always their own rows
-- (needed to resolve which workspaces the actor belongs to).
CREATE POLICY workspace_members_select ON workspace_members FOR
SELECT
  TO nokku_app USING (
    workspace_id = current_workspace_id ()
    OR user_id = current_actor_id ()
  );

CREATE POLICY workspace_members_write ON workspace_members FOR ALL TO nokku_app USING (workspace_id = current_workspace_id ())
WITH
  CHECK (workspace_id = current_workspace_id ());

-- Workspace settings ---------------------------------------------------------
-- Embedded in the workspace list response, so members may read settings of
-- their own workspaces even when no workspace is pinned.
CREATE POLICY workspace_settings_select ON workspace_settings FOR
SELECT
  TO nokku_app USING (
    workspace_id = current_workspace_id ()
    OR is_workspace_member (workspace_id)
  );

CREATE POLICY workspace_settings_write ON workspace_settings FOR ALL TO nokku_app USING (workspace_id = current_workspace_id ())
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

-- Junction tables ------------------------------------------------------------
-- Besides tenant isolation, writes must reference a parent from the same
-- workspace, so a member cannot attach rows to another tenant's entities.
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
