-- mfa_verified_at tracks WHEN the session last completed an MFA
-- challenge, not just whether one happened at any point. Step-up flows
-- (AWS console assume for roles with require_step_up_mfa) reject the
-- request when this timestamp is missing or older than the configured
-- TTL (AUTH_STEP_UP_MFA_TTL). The pre-existing mfa_verified bool
-- remains the cheap "ever?" indicator for audit and policy code paths.
--
-- Backfill: existing rows that have mfa_verified=true get
-- mfa_verified_at=created_at so currently signed-in users aren't
-- bounced through step-up immediately after the migration runs (their
-- session is still "fresh enough" for the TTL window starting from
-- their original sign-in). Rows with mfa_verified=false stay NULL.
ALTER TABLE sessions ADD COLUMN mfa_verified_at TIMESTAMPTZ NULL;
UPDATE sessions SET mfa_verified_at = created_at WHERE mfa_verified = TRUE;
