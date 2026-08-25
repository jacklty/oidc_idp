#!/usr/bin/env bash
# Forge a JWT with session tags and exchange it for temp credentials via real
# AWS STS AssumeRoleWithWebIdentity. Mint args (--tag/--transitive/...) are
# forwarded to mint.py; --save writes the temp creds to an AWS profile.
#
# Principal tags from the JWT (https://aws.amazon.com/tags claim) are
# automatically extracted by STS and become aws:PrincipalTag/<key> on the
# assumed session. No need to pass --tags to the STS call.
set -euo pipefail
cd "$(dirname "$0")"

KEY=${KEY:-keys/private.pem}
ISS=${ISS:-http://localhost:8765}   # MUST equal the IAM OIDC provider URL when tunneled
AUD=${AUD:-sts.amazonaws.com}
SUB=${SUB:-oidc-lab}
SESSION_NAME=${SESSION_NAME:-${SUB}}
ROLE_ARN=${ROLE_ARN:-}
SOURCE_IDENTITY=${SOURCE_IDENTITY:-$SUB}
SAVE_PROFILE=

MINT_ARGS=(--key "$KEY" --iss "$ISS" --aud "$AUD" --sub "$SUB")
if [[ "${SKIP_SOURCE_IDENTITY:-0}" != "1" ]]; then
  if [[ "${EMPTY_SOURCE_IDENTITY:-0}" == "1" ]]; then
    MINT_ARGS+=(--source-identity "")
  else
    MINT_ARGS+=(--source-identity "$SOURCE_IDENTITY")
  fi
fi

while (( $# )); do
  case "$1" in
    --save) SAVE_PROFILE="${2:?--save requires a profile name}"; shift 2 ;;
    --save=*) SAVE_PROFILE="${1#--save=}"; shift ;;
    *) MINT_ARGS+=("$1"); shift ;;
  esac
done

if [[ -z "$ROLE_ARN" ]]; then
  echo "usage: ISS=https://oidc.compulty.com \\
          ROLE_ARN=arn:aws:iam::346992621599:role/compulty \\
          ./exchange.sh --tag User-Grant=admin --tag Group-Grant=devs \\
                        [--save <profile_name>]" >&2
  exit 1
fi

if [[ "${DEBUG:-0}" == "1" ]]; then
  MINT_ARGS+=(--print-payload)
fi

TOKEN=$(./mint.py "${MINT_ARGS[@]}")
echo $TOKEN

STS_JSON=$(aws sts assume-role-with-web-identity \
  --role-arn "$ROLE_ARN" \
  --role-session-name "${SESSION_NAME}" \
  --web-identity-token "$TOKEN" \
  --output json 2>&1) || {
    echo "" >&2
    echo "========================================" >&2
    echo "STS AssumeRoleWithWebIdentity FAILED" >&2
    echo "========================================" >&2
    echo "Role ARN: $ROLE_ARN" >&2
    echo "Session Name: $SESSION_NAME" >&2
    echo "" >&2
    echo "JWT Payload:" >&2
    ./mint.py "${MINT_ARGS[@]}" --print-payload >/dev/null
    echo "" >&2
    echo "AWS Error:" >&2
    echo "$STS_JSON" >&2
    echo "========================================" >&2
    exit 1
  }
echo $STS_JSON | jq .Credentials

if [[ -n "$SAVE_PROFILE" ]]; then
  command -v jq >/dev/null || { echo "error: jq is required for --save" >&2; exit 1; }
  aws configure set aws_access_key_id     "$(jq -r .Credentials.AccessKeyId     <<<"$STS_JSON")" --profile "$SAVE_PROFILE"
  aws configure set aws_secret_access_key "$(jq -r .Credentials.SecretAccessKey <<<"$STS_JSON")" --profile "$SAVE_PROFILE"
  aws configure set aws_session_token     "$(jq -r .Credentials.SessionToken     <<<"$STS_JSON")" --profile "$SAVE_PROFILE"
  if [[ -n "${AWS_DEFAULT_REGION:-}" ]]; then
    aws configure set region "$AWS_DEFAULT_REGION" --profile "$SAVE_PROFILE"
  fi
  EXP=$(jq -r .Credentials.Expiration <<<"$STS_JSON")
  echo "Saved temp creds to AWS profile '$SAVE_PROFILE' (expires $EXP)."
  echo "Try: aws --profile $SAVE_PROFILE s3 ls s3://tsdev-mcf-prod-storage-test/"
else
  printf '%s\n' "$STS_JSON"
fi
