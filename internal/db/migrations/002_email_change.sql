-- The address an email change token carries: the new one on the confirm
-- token, the old one on the revert token.
ALTER TABLE one_time_tokens
ADD COLUMN IF NOT EXISTS email TEXT CHECK (email = lower(email));
