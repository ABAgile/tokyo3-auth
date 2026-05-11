-- See postgres/migrations/010_session_token_split.sql for rationale.
-- SQLite can't ALTER COLUMN, so we recreate the table.

PRAGMA foreign_keys = OFF;

CREATE TABLE sessions_new (
    id                  TEXT     PRIMARY KEY,
    user_id             TEXT     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id           TEXT     NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    access_token_hash   TEXT     NOT NULL UNIQUE,
    refresh_token_hash  TEXT     NOT NULL UNIQUE,
    scopes              TEXT     NOT NULL DEFAULT '[]',
    access_expires_at   DATETIME NOT NULL,
    refresh_expires_at  DATETIME NOT NULL,
    last_activity_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    mfa_verified        INTEGER  NOT NULL DEFAULT 0,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO sessions_new (id, user_id, client_id, access_token_hash, refresh_token_hash, scopes, access_expires_at, refresh_expires_at, last_activity_at, mfa_verified, created_at)
SELECT id, user_id, client_id, access_token_hash, refresh_token_hash, scopes, expires_at, expires_at, last_activity_at, mfa_verified, created_at
FROM sessions;

DROP TABLE sessions;
ALTER TABLE sessions_new RENAME TO sessions;

CREATE INDEX IF NOT EXISTS sessions_access_expires_idx ON sessions(access_expires_at);
CREATE INDEX IF NOT EXISTS sessions_refresh_expires_idx ON sessions(refresh_expires_at);

PRAGMA foreign_keys = ON;
