-- Session helpers used by the RLS policies. These are applied with the base
-- schema so phase one never treats functions referenced by live policies as
-- removed objects.
CREATE OR REPLACE FUNCTION current_workspace_id () RETURNS UUID AS $$
  SELECT NULLIF(current_setting('nokku.workspace_id', TRUE), '')::UUID
$$ LANGUAGE sql STABLE;

CREATE OR REPLACE FUNCTION current_actor_id () RETURNS UUID AS $$
  SELECT NULLIF(current_setting('nokku.actor_id', TRUE), '')::UUID
$$ LANGUAGE sql STABLE;
