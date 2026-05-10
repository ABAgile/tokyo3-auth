-- See postgres/migrations/009_drop_audit_logs.sql for rationale.
DROP INDEX IF EXISTS audit_logs_user_idx;
DROP INDEX IF EXISTS audit_logs_created_idx;
DROP TABLE IF EXISTS audit_logs;
