-- Accounts are global, so a deactivation reaches every workspace the user
-- belongs to.
CREATE OR REPLACE FUNCTION bump_member_state_versions () RETURNS TRIGGER AS $$
DECLARE
  ws UUID;
BEGIN
  FOR ws IN
    UPDATE workspace_state s SET version = version + 1
    FROM workspace_members m
    WHERE m.user_id = NEW.id AND s.workspace_id = m.workspace_id
    RETURNING s.workspace_id
  LOOP
    PERFORM pg_notify('nokku_state', ws::TEXT);
  END LOOP;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER
SET
  search_path = public,
  pg_temp;

CREATE OR REPLACE TRIGGER bump_state_version
AFTER
UPDATE OF active ON users FOR EACH ROW WHEN (OLD.active IS DISTINCT FROM NEW.active)
EXECUTE FUNCTION bump_member_state_versions ();
