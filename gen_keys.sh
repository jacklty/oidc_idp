#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p keys
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out keys/private.pem
openssl rsa -in keys/private.pem -pubout -out keys/public.pem
echo "generated keys/private.pem (signing key) and keys/public.pem (served as JWKS)"
