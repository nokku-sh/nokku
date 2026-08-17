-- Shared SAML service-provider keypair. One per deployment (not per
-- workspace): the SP certificate identifies Nokku itself to every IdP, so a
-- single stable keypair is generated on first boot and reused across
-- instances and restarts.
CREATE TABLE IF NOT EXISTS saml_sp_keys (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  private_key BYTEA NOT NULL,
  certificate TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
