#!/bin/sh
# Unified postgres entrypoint for plain and mTLS modes.
# Must run as root (default before docker-entrypoint.sh drops privileges).
#
# Env vars:
#   PG_INIT_SCRIPT      path to the initdb script to install (e.g. /shared/postgres/db-init.sh)
#   POSTGRES_SSL_CERT   (mTLS only) server certificate PEM path
#   POSTGRES_SSL_KEY    (mTLS only) server private key PEM path
#   POSTGRES_SSL_CA     (mTLS only) CA certificate PEM path
set -eu

if [ -n "${PG_INIT_SCRIPT:-}" ]; then
  cp "$PG_INIT_SCRIPT" /docker-entrypoint-initdb.d/init.sh
  chmod 755 /docker-entrypoint-initdb.d/init.sh
fi

if [ -n "${POSTGRES_SSL_CERT:-}" ]; then
  cp "$POSTGRES_SSL_KEY" /tmp/server.key
  chown 70:70 /tmp/server.key
  chmod 600 /tmp/server.key
  exec docker-entrypoint.sh postgres \
    -c ssl=on \
    -c "ssl_cert_file=$POSTGRES_SSL_CERT" \
    -c ssl_key_file=/tmp/server.key \
    -c "ssl_ca_file=$POSTGRES_SSL_CA" \
    -c "hba_file=/shared/postgres/pg_hba_cert.conf"
fi

exec docker-entrypoint.sh postgres
