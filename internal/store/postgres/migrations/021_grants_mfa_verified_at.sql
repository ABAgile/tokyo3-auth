-- Records when (if ever) the user completed an MFA challenge as part of the
-- authentication that produced this authorization code. NULL means password
-- only; the token endpoint derives the session's mfa_verified flag from it
-- rather than assuming MFA happened.
ALTER TABLE grants ADD COLUMN mfa_verified_at TIMESTAMPTZ NULL;
