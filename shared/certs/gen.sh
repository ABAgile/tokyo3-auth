#!/usr/bin/env bash
# Generate TLS/mTLS leaf certs for the docker compose mTLS overlay, signed by
# mkcert's local CA. Run from the repo root:  bash shared/certs/gen.sh
# Requires: mkcert (auto-installed via `go install` if missing — Go environment
# must already be set up so the mkcert binary lands on PATH).
#
# Uses the abagile/mkcert fork, which adds support for setting Subject CN from
# the first hostname argument. PostgreSQL `cert` auth matches the connecting
# role against Subject CN, so each db client cert passes the role name first
# and any DNS SANs after it.
#
# `mkcert -install` adds the root CA to the OS + browser trust stores so
# authd's HTTPS server cert is trusted without warnings. Re-running this
# script regenerates leaf certs in place.

set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"

# Load .env from the repo root if present — mirrors docker compose behaviour so
# AUTH_ADMIN_DB_USERNAME / AUTH_DB_USERNAME stay in sync with the DSNs.
REPO_ROOT="$(cd "$DIR/../.." && pwd)"
if [[ -f "$REPO_ROOT/.env" ]]; then
  set -a
  # shellcheck source=/dev/null
  source "$REPO_ROOT/.env"
  set +a
fi
ADMIN_USERNAME="${AUTH_ADMIN_DB_USERNAME:-auth_admin}"
APP_USERNAME="${AUTH_DB_USERNAME:-auth_app}"

step() { printf '  %-34s' "$1..."; }
ok()   { echo "ok"; }

# ── Ensure mkcert (abagile fork) is available ────────────────────────────────
if ! command -v mkcert >/dev/null 2>&1; then
  step "installing mkcert"
  go install github.com/abagile/mkcert@add-cn >/dev/null
  ok
fi

# Install mkcert root CA into OS + browser trust stores (idempotent — mkcert
# does not overwrite an existing CA at $(mkcert -CAROOT)).
step "mkcert -install"
mkcert -install >/dev/null 2>&1
ok

CAROOT="$(mkcert -CAROOT)"

# ── Helpers ──────────────────────────────────────────────────────────────────

# Server cert (serverAuth + clientAuth EKU). Args after $1 are passed through;
# the fork uses the first hostname as Subject CN.
mkc_server() {
  local name=$1; shift
  step "$name"
  mkcert -cert-file "$DIR/$name.crt" -key-file "$DIR/$name.key" "$@" >/dev/null 2>&1
  ok
}

# Client cert (clientAuth-only EKU). Args after $1 are passed through; the
# fork uses the first hostname as Subject CN — for db clients this is the
# role name, for service clients it's the service identity, etc.
mkc_client() {
  local name=$1; shift
  step "$name"
  mkcert -client -cert-file "$DIR/$name.crt" -key-file "$DIR/$name.key" "$@" >/dev/null 2>&1
  ok
}

# ── Server certs ─────────────────────────────────────────────────────────────
# `.localhost` and any subdomain are reserved (RFC 6761) and resolve to
# 127.0.0.1 on modern systems — no /etc/hosts entries needed. The docker
# service hostname (and a network alias for `db.localhost`) covers in-network
# access. localhost / 127.0.0.1 SANs on authd-server let
# AUTH_ISSUER=https://localhost:8443 (the run-mtls default) validate without
# a cert mismatch.
mkc_server "authd-server"  authd  auth.localhost  teleport.localhost  github.com  api.github.com  localhost  127.0.0.1
mkc_server "db-server"     db     db.localhost    localhost  127.0.0.1
mkc_server "nats-server"   nats   nats.localhost  localhost  127.0.0.1

# ── Client certs — NATS (transport identity only) ────────────────────────────
mkc_client "authd-nats-client" authd

# ── Client certs — PostgreSQL (CN must match the DB role for cert auth) ──────
# Role name first → fork sets it as Subject CN. SAN follows.
mkc_client "authd-admin-db-client" "$ADMIN_USERNAME" authd
mkc_client "authd-app-db-client"   "$APP_USERNAME"   authd

# ── Client cert — outbound SCIM provisioning ─────────────────────────────────
# Used by AUTH_SCIM_MTLS_CERT/KEY when an app_integrations row is in mTLS
# mode. CN=authd is the stable identity downstreams allow-list as "the IdP";
# SANs are advisory (servers don't validate client-cert hostnames). Same root
# CA as everything else, so a downstream that already trusts the mkcert CA for
# its own server cert will accept this client cert with no extra config.
mkc_client "authd-scim-client"  authd  auth.localhost

echo ""
echo "leaf certs written to shared/certs/"
echo "CA: $CAROOT/rootCA.pem (mkcert root, trusted via mkcert -install)"
echo "next: docker compose -f docker-compose.yml -f docker-compose.mtls.yml up -d"
