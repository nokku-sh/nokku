CREATE SCHEMA IF NOT EXISTS audit;

CREATE TABLE IF NOT EXISTS audit.audit_logs (
  id UUID NOT NULL DEFAULT uuidv7(),
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  workspace_id UUID REFERENCES public.workspaces (id) ON DELETE CASCADE,
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

-- Add the column to tables created before it existed.
ALTER TABLE audit.audit_logs ADD COLUMN IF NOT EXISTS actor_email TEXT;

CREATE INDEX IF NOT EXISTS idx_audit_logs_workspace_time ON audit.audit_logs (workspace_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit.audit_logs (actor_id, timestamp DESC);
