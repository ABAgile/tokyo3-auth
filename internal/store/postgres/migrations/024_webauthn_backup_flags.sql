-- Persist the WebAuthn authenticator flags go-webauthn checks on every
-- assertion. backup_eligible (BE) never changes for a credential: true
-- for synced passkeys, false for hardware keys. Without it every synced
-- passkey failed login with "Backup Eligible flag inconsistency".
--
-- backup_eligible is NULL for credentials enrolled before this
-- migration; the first successful assertion records the authenticator's
-- value, after which the consistency check applies.
-- backup_state (BS) is the latest observed sync state and may change.
ALTER TABLE webauthn_credentials ADD COLUMN backup_eligible BOOLEAN NULL;
ALTER TABLE webauthn_credentials ADD COLUMN backup_state BOOLEAN NOT NULL DEFAULT FALSE;
