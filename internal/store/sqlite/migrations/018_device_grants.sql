-- See postgres/018 for design notes. SQLite uses TEXT for TIMESTAMPs
-- and INTEGER for booleans (matching the rest of this schema).
CREATE TABLE device_grants (
    id                 TEXT PRIMARY KEY,
    device_code_hash   TEXT NOT NULL UNIQUE,
    user_code_hash     TEXT NOT NULL UNIQUE,
    client_id          TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    scopes             TEXT NOT NULL DEFAULT '',
    status             TEXT NOT NULL,
    user_id            TEXT NULL REFERENCES users(id) ON DELETE SET NULL,
    mfa_verified       INTEGER NOT NULL DEFAULT 0,
    mfa_verified_at    TIMESTAMP NULL,
    approver_ip        TEXT NOT NULL DEFAULT '',
    interval_sec       INTEGER NOT NULL DEFAULT 5,
    last_polled_at     TIMESTAMP NULL,
    created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at         TIMESTAMP NOT NULL
);
CREATE INDEX device_grants_expires_idx ON device_grants(expires_at);
