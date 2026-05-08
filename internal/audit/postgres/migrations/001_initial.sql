CREATE TABLE audit_logs (
    id          UUID         PRIMARY KEY,
    user_id     UUID,
    client_id   UUID,
    action      TEXT         NOT NULL,
    ip          TEXT         NOT NULL DEFAULT '',
    user_agent  TEXT         NOT NULL DEFAULT '',
    metadata    JSONB        NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ  NOT NULL
);
CREATE INDEX idx_audit_user_id    ON audit_logs(user_id);
CREATE INDEX idx_audit_client_id  ON audit_logs(client_id);
CREATE INDEX idx_audit_created_at ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_action     ON audit_logs(action);
