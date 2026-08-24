#!/usr/bin/env bash
# Issues a local CA and a server certificate for the dev broker.
#
# The dev loop runs TLS like every other deployment shape does. There is no
# cleartext listener to fall back to, on purpose: the CONNECT password is a
# device token, and a plaintext shortcut in development is how one ends up on
# a wire that matters. This script exists so that rule costs nothing.
#
# Output (gitignored) in scripts/dev-cert/:
#   ca.pem       trust anchor, hand this to a client
#   server.pem   chain the broker serves
#   server.key   its private key
#
# All-ECDSA, mirroring production: the issued chain there is a P-256 leaf
# under an ECDSA intermediate anchored at ISRG Root X2, so a device built to
# verify only P-256 and P-384 works against both.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$here/dev-cert"
days="${PIGEONHOLE_DEV_CERT_DAYS:-90}"
# Names the dev certificate is valid for. A client verifies the name, so a
# broker reached by an address the certificate does not carry will be
# refused, which is the behaviour worth keeping honest in development too.
names="${PIGEONHOLE_DEV_CERT_NAMES:-DNS:localhost,IP:127.0.0.1,IP:::1}"

mkdir -p "$out"
chmod 700 "$out"

openssl ecparam -name prime256v1 -genkey -noout -out "$out/ca.key" 2>/dev/null
openssl req -x509 -new -key "$out/ca.key" -sha256 -days "$days" \
  -subj "/CN=pigeonhole dev CA" -out "$out/ca.pem" 2>/dev/null

openssl ecparam -name prime256v1 -genkey -noout -out "$out/server.key" 2>/dev/null
openssl req -new -key "$out/server.key" -subj "/CN=localhost" -out "$out/server.csr" 2>/dev/null
openssl x509 -req -in "$out/server.csr" -CA "$out/ca.pem" -CAkey "$out/ca.key" \
  -CAcreateserial -days "$days" -sha256 \
  -extfile <(printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\n' "$names") \
  -out "$out/server.pem" 2>/dev/null

rm -f "$out/server.csr" "$out/ca.srl"
chmod 600 "$out"/*.key
chmod 644 "$out/ca.pem" "$out/server.pem"

cat <<EOF
issued for $names, valid $days days

  PIGEONHOLE_TLS_CERT=$out/server.pem
  PIGEONHOLE_TLS_KEY=$out/server.key

clients verify against $out/ca.pem
EOF
