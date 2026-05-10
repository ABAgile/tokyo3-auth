-- The audit journal is now exclusively NATS JetStream (subject auth.audit.events,
-- stream auth_audit). The local mirror in audit_logs is gone — authd publishes
-- synchronously and fails the originating request when the journal is unreachable
-- (fail-closed, PCI-DSS 10.2 / 10.3). The auth_audit projection (separate database,
-- written by the auth-audit consumer) remains the queryable read source.
DROP INDEX IF EXISTS audit_logs_user_idx;
DROP INDEX IF EXISTS audit_logs_created_idx;
DROP TABLE IF EXISTS audit_logs;
