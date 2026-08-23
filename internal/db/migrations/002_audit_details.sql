-- Add free-form detail metadata to audit events for SIEM/analytics, and
-- extend the read policy so a principal can see its own global (non-tenant)
-- events under RLS. This removes the need for the BYPASSRLS read path used
-- for user-scoped activity.

ALTER TABLE audit.audit_logs
  ADD COLUMN IF NOT EXISTS details JSONB NOT NULL DEFAULT '{}';

DROP POLICY IF EXISTS audit_logs_select ON audit.audit_logs;

CREATE POLICY audit_logs_select ON audit.audit_logs
  FOR SELECT TO nokku_app
  USING (
    workspace_id = current_workspace_id ()
    OR (workspace_id IS NULL AND actor_id = current_actor_id ())
  );
