-- See postgres/migrations/024_webauthn_backup_flags.sql. backup_eligible
-- NULL = enrolled before this migration; backfilled on next assertion.
ALTER TABLE webauthn_credentials ADD COLUMN backup_eligible INTEGER NULL;
ALTER TABLE webauthn_credentials ADD COLUMN backup_state INTEGER NOT NULL DEFAULT 0;
