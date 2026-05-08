CREATE TABLE IF NOT EXISTS totp_credentials (
    id               TEXT     PRIMARY KEY,
    user_id          TEXT     NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    encrypted_secret BLOB     NOT NULL,
    encrypted_dek    BLOB     NOT NULL,
    enabled          INTEGER  NOT NULL DEFAULT 0,
    created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id              TEXT     PRIMARY KEY,
    user_id         TEXT     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id   BLOB     NOT NULL UNIQUE,
    public_key      BLOB     NOT NULL,
    aaguid          BLOB     NOT NULL DEFAULT (X'00000000000000000000000000000000'),
    sign_count      INTEGER  NOT NULL DEFAULT 0,
    device_name     TEXT     NOT NULL DEFAULT '',
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS webauthn_creds_user_idx ON webauthn_credentials(user_id);

CREATE TABLE IF NOT EXISTS webauthn_sessions (
    id           TEXT     PRIMARY KEY,
    user_id      TEXT     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_data BLOB     NOT NULL,
    purpose      TEXT     NOT NULL,
    expires_at   DATETIME NOT NULL DEFAULT (datetime('now', '+5 minutes')),
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS webauthn_sessions_expires_idx ON webauthn_sessions(expires_at);
