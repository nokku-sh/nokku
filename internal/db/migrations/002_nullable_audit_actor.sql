-- Audit actors are written verbatim from the request identity: unknown
-- actors stay empty instead of carrying a placeholder UUID.
ALTER TABLE audit.audit_logs ALTER COLUMN actor_id DROP NOT NULL;

UPDATE
  audit.audit_logs
SET
  actor_id = NULL
WHERE
  actor_id = '00000000-0000-0000-0000-000000000000';
