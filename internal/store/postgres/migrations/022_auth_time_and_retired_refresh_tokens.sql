-- auth_time: when the user actually authenticated (password, or password
-- plus MFA), carried from the authorization code onto the session so ID
-- tokens report the real login time (OIDC Core §2 auth_time) instead of the
-- moment the token was minted, and refreshed ID tokens keep the original.
-- Existing sessions fall back to their creation time, which is when the
-- login that produced them completed; machine sessions stay NULL.
ALTER TABLE grants   ADD COLUMN auth_time TIMESTAMPTZ NULL;
ALTER TABLE sessions ADD COLUMN auth_time TIMESTAMPTZ NULL;
UPDATE sessions SET auth_time = created_at WHERE user_id IS NOT NULL;

-- Every refresh token a session has already rotated away from. Presenting
-- one again is a replay (RFC 9700 §4.14): the token was copied, so the
-- session is revoked. Rows go with their session (cascade).
CREATE TABLE retired_refresh_tokens (
    token_hash TEXT        PRIMARY KEY,
    session_id UUID        NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    retired_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX retired_refresh_tokens_session_idx ON retired_refresh_tokens(session_id);
