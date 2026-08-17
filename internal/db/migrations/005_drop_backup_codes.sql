-- Drop the backup_codes table: backup codes moved into kagi's credentials
-- table (type = 'backup_code', subject = sha256 hash). Codes are deleted on
-- use, so the credential count is the number of remaining codes.

DROP TABLE IF EXISTS backup_codes;
