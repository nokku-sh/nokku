-- Ensure only one default CA per workspace
CREATE OR REPLACE FUNCTION enforce_single_default_ca () RETURNS TRIGGER AS $$
BEGIN
  IF NEW.is_default = TRUE THEN
    UPDATE certificate_authorities
    SET is_default = FALSE
    WHERE workspace_id = NEW.workspace_id
      AND id != NEW.id
      AND is_default = TRUE;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_single_default_ca BEFORE INSERT
OR
UPDATE OF is_default ON certificate_authorities FOR EACH ROW WHEN (NEW.is_default = TRUE)
EXECUTE FUNCTION enforce_single_default_ca ();

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column () RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Automatically create triggers for all tables with updated_at column
DO $$
DECLARE
  t RECORD;
  trigger_name TEXT;
BEGIN
  FOR t IN
    SELECT table_name
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND column_name = 'updated_at'
  LOOP
    trigger_name := 'update_' || t.table_name || '_updated_at';

    EXECUTE format(
      'CREATE OR REPLACE TRIGGER %I BEFORE UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()',
      trigger_name,
      t.table_name
    );
  END LOOP;
END;
$$;
