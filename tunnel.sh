#!/usr/bin/env bash
# Start the OIDC IdP behind a Cloudflare quick tunnel and print the public URLs.
# The IAM OIDC provider must point at the printed issuer, and idp.py's --issuer
# must equal it — this script sets that automatically.
#
# NOTE: quick-tunnel hostnames (trycloudflare.com) change every restart, and
# account-less tunnels can be throttled. If the hostname changes you must
# re-register the IAM OIDC provider + role trust. For a stable URL use a named
# tunnel with your own domain (see README).
set -euo pipefail
cd "$(dirname "$0")"

PORT=${PORT:-8765}
SECRET=${SECRET:-labsecret}
KEY_DIR=${KEY_DIR:-keys}
ISSUER_OVERRIDE=${ISSUER:-}   # set to use an existing named-tunnel hostname

if [[ ! -f "$KEY_DIR/private.pem" ]]; then
  echo "no keys found — run ./gen_keys.sh" >&2
  exit 1
fi

IDP_LOG=idp.log
TAIL_PIDS=""
cleanup() {
  kill ${IDP_PID:-} ${CF_PID:-} ${TAIL_PIDS:-} 2>/dev/null || true
}
trap cleanup EXIT

start_tunnel() {
  CLOUDFLARED_LOG=$(mktemp)
  cloudflared tunnel --url "http://localhost:$PORT" >"$CLOUDFLARED_LOG" 2>&1 &
  CF_PID=$!
}

wait_for_hostname() {
  local max=${1:-90}
  for _ in $(seq 1 "$max"); do
    HOST=$(grep -oE "https://[a-z0-9-]+\.trycloudflare\.com" "$CLOUDFLARED_LOG" | head -1 | sed 's#https://##')
    [[ -n "$HOST" ]] && return 0
    printf "." >&2
    sleep 1
  done
  return 1
}

if [[ -n "$ISSUER_OVERRIDE" ]]; then
  # Named-tunnel mode: idp.py uses the stable hostname; cloudflared runs via
  # its own config (e.g.  cloudflared tunnel run <name>). See README.
  HOST="${ISSUER_OVERRIDE#https://}"
  HOST="${HOST%%/*}"
  echo "using named-tunnel issuer https://$HOST (start cloudflared separately)"
else
  echo "waiting for Cloudflare to assign a quick-tunnel hostname..." >&2
  start_tunnel
  if ! wait_for_hostname 60; then
    echo >&2
    echo "cloudflared stalled — restarting once and retrying..." >&2
    kill "$CF_PID" 2>/dev/null
    sleep 2
    start_tunnel
    wait_for_hostname 90 || {
      echo >&2
      echo "still no hostname; last cloudflared output:" >&2
      tail -20 "$CLOUDFLARED_LOG" >&2
      exit 1
    }
  fi
  echo >&2
fi

python3 idp.py --port "$PORT" --issuer "https://$HOST" --secret "$SECRET" --key-dir "$KEY_DIR" >"$IDP_LOG" 2>&1 &
IDP_PID=$!
sleep 1

echo "issuer    = https://$HOST"
echo "jwks_uri  = https://$HOST/.well-known/jwks.json"
echo "discovery = https://$HOST/.well-known/openid-configuration"
echo "token     = POST https://$HOST/token  (Authorization: Bearer $SECRET)"
echo
echo "Use ISS=https://$HOST ./exchange.sh --tag Team=eng --transitive Team"
if [[ -z "$ISSUER_OVERRIDE" ]]; then
  echo
  echo "NOTE: quick-tunnel hostname changes on restart — re-register the IAM"
  echo "OIDC provider if it changes. Ctrl-C to stop."
fi
if [[ -n "$ISSUER_OVERRIDE" ]]; then
  LOGS=("$IDP_LOG")
else
  LOGS=("$CLOUDFLARED_LOG" "$IDP_LOG")
fi
for log in "${LOGS[@]}"; do
  tail -F -n +1 "$log" &
  TAIL_PIDS="$TAIL_PIDS $!"
done
echo
echo "streaming logs (Ctrl-C to stop): ${LOGS[*]}"

if [[ -n "$ISSUER_OVERRIDE" ]]; then
  wait "$IDP_PID"
else
  wait "$CF_PID"
fi
