-- See postgres/022 for design notes.
ALTER TABLE grants   ADD COLUMN auth_time TIMESTAMP NULL;
ALTER TABLE sessions ADD COLUMN auth_time TIMESTAMP NULL;
UPDATE sessions SET auth_time = created_at WHERE user_id IS NOT NULL;

CREATE TABLE retired_refresh_tokens (
    token_hash TEXT     PRIMARY KEY,
    session_id TEXT     NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    retired_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX retired_refresh_tokens_session_idx ON retired_refresh_tokens(session_id);
