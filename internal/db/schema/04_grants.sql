DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nokku_app') THEN
	 CREATE ROLE nokku_app NOLOGIN;
  END IF;
END $$;

-- Schema permissions
GRANT USAGE ON SCHEMA public TO nokku_app;

-- Table grants for nokku_app
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO nokku_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO nokku_app;

-- Default privileges for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public 
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO nokku_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public 
  GRANT USAGE, SELECT ON SEQUENCES TO nokku_app;
