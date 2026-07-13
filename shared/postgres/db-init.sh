#!/usr/bin/env bash
# Creates the app role (DML-only: SELECT/INSERT/UPDATE/DELETE, no DDL) for the
# standalone demo database. Production deployments should provide their own DB.
set -euo pipefail

psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" \
     --dbname   "$POSTGRES_DB" \
     --no-psqlrc <<'SQL'

CREATE USER authd_app;

GRANT CONNECT ON DATABASE authd TO authd_app;
GRANT USAGE   ON SCHEMA  public TO authd_app;

-- Pre-grant DML on all future tables and sequences created by the migration owner.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO authd_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO authd_app;

SQL
