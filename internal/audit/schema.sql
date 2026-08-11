CREATE SCHEMA IF NOT EXISTS audit;

CREATE TABLE IF NOT EXISTS audit.audit_logs (
  id UUID NOT NULL DEFAULT uuidv7(),
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  workspace_id UUID REFERENCES public.workspaces (id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  actor_id UUID NOT NULL,
  actor_type TEXT NOT NULL,
  actor_email TEXT,
  ip_address TEXT,
  user_agent TEXT,
  status_code TEXT,
  PRIMARY KEY (timestamp, id)
)
PARTITION BY
  RANGE (timestamp);

CREATE INDEX IF NOT EXISTS idx_audit_logs_workspace_time ON audit.audit_logs (workspace_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit.audit_logs (actor_id, timestamp DESC);

-- Access for the application roles (see internal/db/schema/04_grants.sql).
-- This file runs as the table owner and is executed idempotently at startup.
GRANT USAGE ON SCHEMA audit TO nokku_app, nokku_system;

GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA audit TO nokku_app;

GRANT SELECT, INSERT, DELETE ON ALL TABLES IN SCHEMA audit TO nokku_system;

-- Partitions created later by the retention job inherit these.
ALTER DEFAULT PRIVILEGES IN SCHEMA audit
  GRANT SELECT, INSERT ON TABLES TO nokku_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA audit
  GRANT SELECT, INSERT, DELETE ON TABLES TO nokku_system;

ALTER TABLE audit.audit_logs ENABLE ROW LEVEL SECURITY;

ALTER TABLE audit.audit_logs FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname = 'audit'
      AND tablename = 'audit_logs'
      AND policyname = 'audit_logs_select'
  ) THEN
    CREATE POLICY audit_logs_select ON audit.audit_logs FOR
    SELECT
      TO nokku_app USING (workspace_id = current_workspace_id ());
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname = 'audit'
      AND tablename = 'audit_logs'
      AND policyname = 'audit_logs_insert'
  ) THEN
    CREATE POLICY audit_logs_insert ON audit.audit_logs FOR INSERT TO nokku_app
    WITH
      CHECK (TRUE);
  END IF;
END $$;
