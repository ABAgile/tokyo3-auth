#!/usr/bin/env bash
# Generate dev TLS material for the auth Compose rig.
#
# Workload mTLS material is CA-managed by cert-agentd on the tokyo3 mesh. This
# script reuses or mints a wildcard dev.localhost certificate for local HTTPS
# services; it does not replace CA-managed workload identities.

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

CAROOT="$(mkcert -CAROOT)"

step "mkcert -install"
doas env CAROOT=$CAROOT `command -v mkcert` -install >/dev/null
ok

step "traefik-ca.crt (mkcert root)"
rm -f "$OUT/ca.crt"
cp "$CAROOT/rootCA.pem" "$OUT/traefik-ca.crt"
ok

step "dev.localhost (wildcard cert)"
if [[ ! -s "$OUT/dev.localhost.crt" || ! -s "$OUT/dev.localhost.key" ]]; then
  mkcert -cert-file "$OUT/dev.localhost.crt" -key-file "$OUT/dev.localhost.key" \
    '*.dev.localhost' localhost 127.0.0.1 >/dev/null
fi
ok

echo ""
echo "dev TLS material written to shared/certs/"
echo "CA: $OUT/traefik-ca.crt (mkcert root, trusted via mkcert -install)"
echo "cert: $OUT/dev.localhost.crt"
echo "next: make docker-up"
