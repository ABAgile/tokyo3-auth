#!/bin/sh
# Installs the optional initdb script, then delegates to the upstream entrypoint.
set -eu

if [ -n "${PG_INIT_SCRIPT:-}" ]; then
  cp "$PG_INIT_SCRIPT" /docker-entrypoint-initdb.d/init.sh
  chmod 755 /docker-entrypoint-initdb.d/init.sh
fi

exec docker-entrypoint.sh postgres
