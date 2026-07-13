#!/usr/bin/env bash
# Generate dev TLS material for the auth docker-compose rig.
#
# Workload mTLS material is CA-managed by cert-agentd on the tokyo3 mesh. This
# script only mints the host-facing Traefik edge certificate used by the local
# browser/Teleport development flow.

set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$DIR"

mkdir -p "$OUT"

step() { printf '  %-34s' "$1..."; }
ok() { echo "ok"; }

if ! command -v mkcert >/dev/null 2>&1; then
  step "installing mkcert"
  go install github.com/abagile/mkcert@add-cn >/dev/null
  ok
fi

step "mkcert -install"
mkcert -install >/dev/null 2>&1
ok

CAROOT="$(mkcert -CAROOT)"

step "traefik-ca.crt (mkcert root)"
rm -f "$OUT/ca.crt"
cp "$CAROOT/rootCA.pem" "$OUT/traefik-ca.crt"
ok

step "traefik (server cert)"
mkcert -cert-file "$OUT/traefik.crt" -key-file "$OUT/traefik.key" \
  auth.localhost teleport.localhost github.com api.github.com traefik.localhost localhost 127.0.0.1 >/dev/null 2>&1
ok

echo ""
echo "dev TLS material written to shared/certs/"
echo "CA: $CAROOT/rootCA.pem (mkcert root, trusted via mkcert -install)"
echo "next: make docker-up"
