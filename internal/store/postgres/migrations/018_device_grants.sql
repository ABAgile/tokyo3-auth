-- device_grants backs RFC 8628 (OAuth 2.0 Device Authorization Grant).
--
-- One row is born from POST /device_authorization (status=pending), gets
-- approved or denied at /device/confirm (the user-facing page), and is
-- consumed at POST /token (status=redeemed). Approver MFA state is
-- captured onto the row at approval time, not re-read at redemption,
-- so the issued session inherits a stable MFA snapshot even if the
-- approver's portal session mutates between approve and redeem.
--
-- device_code and user_code are bearer-shaped: the device_code is what
-- the CLI sends back to /token (long, opaque, never leaves the
-- device); the user_code is what the user reads off the CLI and types
-- into the browser at /device (short, human-typeable, format
-- XXXX-WXYZ). Both are stored hashed so an admin-side leak of the
-- table doesn't hand out usable codes.
CREATE TABLE device_grants (
    id                 UUID PRIMARY KEY,
    device_code_hash   TEXT NOT NULL UNIQUE,
    user_code_hash     TEXT NOT NULL UNIQUE,
    client_id          UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    scopes             TEXT NOT NULL DEFAULT '',
    status             TEXT NOT NULL,
    user_id            UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    mfa_verified       BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_verified_at    TIMESTAMPTZ NULL,
    approver_ip        TEXT NOT NULL DEFAULT '',
    interval_sec       INTEGER NOT NULL DEFAULT 5,
    last_polled_at     TIMESTAMPTZ NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at         TIMESTAMPTZ NOT NULL
);
CREATE INDEX device_grants_expires_idx ON device_grants(expires_at);
