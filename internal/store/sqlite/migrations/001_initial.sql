CREATE TABLE IF NOT EXISTS users (
    id                  TEXT     PRIMARY KEY,
    email               TEXT     NOT NULL UNIQUE,
    password_hash       TEXT     NOT NULL DEFAULT '',
    name                TEXT     NOT NULL DEFAULT '',
    active              INTEGER  NOT NULL DEFAULT 1,
    scim_external_id    TEXT     NOT NULL DEFAULT '',
    mfa_enabled         INTEGER  NOT NULL DEFAULT 0,
    password_changed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    failed_attempts     INTEGER  NOT NULL DEFAULT 0,
    locked_until        DATETIME,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS clients (
    id                  TEXT     PRIMARY KEY,
    client_id           TEXT     NOT NULL UNIQUE,
    client_secret_hash  TEXT     NOT NULL DEFAULT '',
    name                TEXT     NOT NULL,
    redirect_uris       TEXT     NOT NULL DEFAULT '[]',
    scopes              TEXT     NOT NULL DEFAULT '[]',
    public              INTEGER  NOT NULL DEFAULT 0,
    secret_rotated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS grants (
    id              TEXT     PRIMARY KEY,
    user_id         TEXT     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id       TEXT     NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    code_hash       TEXT     NOT NULL UNIQUE,
    code_challenge  TEXT     NOT NULL DEFAULT '',
    nonce           TEXT     NOT NULL DEFAULT '',
    scopes          TEXT     NOT NULL DEFAULT '[]',
    redirect_uri    TEXT     NOT NULL DEFAULT '',
    expires_at      DATETIME NOT NULL,
    used_at         DATETIME
);

CREATE INDEX IF NOT EXISTS grants_expires_idx ON grants(expires_at);

CREATE TABLE IF NOT EXISTS sessions (
    id                  TEXT     PRIMARY KEY,
    user_id             TEXT     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id           TEXT     NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    access_token_hash   TEXT     NOT NULL UNIQUE,
    refresh_token_hash  TEXT     NOT NULL UNIQUE,
    scopes              TEXT     NOT NULL DEFAULT '[]',
    expires_at          DATETIME NOT NULL,
    last_activity_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    mfa_verified        INTEGER  NOT NULL DEFAULT 0,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS scim_tokens (
    id          TEXT     PRIMARY KEY,
    token_hash  TEXT     NOT NULL UNIQUE,
    description TEXT     NOT NULL DEFAULT '',
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS signing_keys (
    id                      TEXT     PRIMARY KEY,
    encrypted_private_key   BLOB     NOT NULL,
    encrypted_dek           BLOB     NOT NULL,
    algorithm               TEXT     NOT NULL DEFAULT 'RS256',
    kid                     TEXT     NOT NULL UNIQUE,
    active                  INTEGER  NOT NULL DEFAULT 1,
    created_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id          TEXT     PRIMARY KEY,
    user_id     TEXT     REFERENCES users(id) ON DELETE SET NULL,
    client_id   TEXT     REFERENCES clients(id) ON DELETE SET NULL,
    action      TEXT     NOT NULL,
    ip          TEXT     NOT NULL DEFAULT '',
    user_agent  TEXT     NOT NULL DEFAULT '',
    metadata    TEXT     NOT NULL DEFAULT '{}',
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS audit_logs_created_idx ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS audit_logs_user_idx    ON audit_logs(user_id, created_at DESC);
