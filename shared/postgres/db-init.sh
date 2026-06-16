#!/usr/bin/env bash
# Creates the app role (DML-only: SELECT/INSERT/UPDATE/DELETE, no DDL) for the auth database.
# Runs once on first postgres startup via docker-entrypoint-initdb.d/.
#
# Required env vars (set on the db container):
#   AUTHD_DB_USERNAME   app role username (default: auth_app)
#   AUTHD_DB_PASSWORD   app role password
set -euo pipefail

: "${AUTHD_DB_USERNAME:=auth_app}"

psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" \
     --dbname   "$POSTGRES_DB"   \
     -v app_user="$AUTHD_DB_USERNAME" \
     -v app_pw="$AUTHD_DB_PASSWORD" \
     --no-psqlrc <<'SQL'

CREATE USER :"app_user" WITH PASSWORD :'app_pw';

GRANT CONNECT ON DATABASE authdb TO :"app_user";
GRANT USAGE   ON SCHEMA  public  TO :"app_user";

-- Pre-grant DML on all future tables and sequences created by the migration owner (POSTGRES_USER).
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO :"app_user";
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO :"app_user";

SQL
