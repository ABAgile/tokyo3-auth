-- See postgres/021: NULL = password-only authentication.
ALTER TABLE grants ADD COLUMN mfa_verified_at TIMESTAMP NULL;
