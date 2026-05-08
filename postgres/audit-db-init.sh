#!/usr/bin/env bash
# Sets up the audit database schema permissions.
# Schema (audit_logs table) is managed by versioned migrations run by
# auth-audit at startup via AUTH_AUDIT_DATABASE_URL.
# Runs once on first postgres startup via docker-entrypoint-initdb.d/.
#
# POSTGRES_USER (the auth_audit owner) owns the database and has full rights.
# auth-audit uses a single AUTH_AUDIT_DATABASE_URL with this credential for
# schema migrations, writes, and queries.
set -euo pipefail

psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" \
     --dbname   "$POSTGRES_DB"   \
     --no-psqlrc <<'SQL'

-- Ensure the public schema is owned by the audit role so migrations can create tables.
ALTER SCHEMA public OWNER TO CURRENT_USER;

SQL
