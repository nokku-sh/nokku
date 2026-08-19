-- Sessions: track last activity for kagi's idle-timeout enforcement.
-- Added separately from 002_auth.sql so deployments that already applied that
-- migration get the column instead of silently missing it.

ALTER TABLE sessions
  ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ;