DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nokku_app') THEN
	 CREATE ROLE nokku_app NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nokku_system') THEN
	 CREATE ROLE nokku_system NOLOGIN BYPASSRLS;
  END IF;
END $$;

-- nokku_system bypasses RLS for internal operations (bootstrap, webhooks,
-- background jobs, pre-auth lookups). LOGIN and the password for nokku_app
-- are managed at startup by the application (see internal/db/migrate.go).
GRANT nokku_system TO nokku_app;

-- Schema permissions
GRANT USAGE ON SCHEMA public TO nokku_app, nokku_system;

-- Table grants for nokku_app and nokku_system
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO nokku_app, nokku_system;

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO nokku_app, nokku_system;

-- Default privileges for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO nokku_app, nokku_system;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO nokku_app, nokku_system;
