#!/usr/bin/env bash
# Test script for OIDC trust policy failures.
# Run from oidc_idp/ directory.
set -uo pipefail
cd "$(dirname "$0")"

: "${ISS:?ISS not set (e.g. https://oidc.compulty.com)}"
: "${ROLE_ARN:?ROLE_ARN not set (e.g. arn:aws:iam::346992621599:role/compulty)}"

export ISS ROLE_ARN

PASSED=0
TOTAL=0

run_test() {
  local name="$1"
  local expect_success="${2:-false}"
  shift 2
  echo ""
  echo "****************************************"
  echo "TEST: $name"
  echo "****************************************"
  echo "CMD: $*"
  echo ""
  TOTAL=$((TOTAL + 1))
  
  OUTPUT=$("$@" 2>&1)
  EXIT_CODE=$?
  
  if [[ $EXIT_CODE -eq 0 ]]; then
    if [[ "$expect_success" == "true" ]]; then
      echo "✓ EXPECTED: command succeeded"
      echo "$OUTPUT" | tail -5
      PASSED=$((PASSED + 1))
    else
      echo "✗ UNEXPECTED: command succeeded (expected AWS error)"
      echo "$OUTPUT" | tail -5
    fi
  else
    if echo "$OUTPUT" | grep -q "An error occurred.*when calling the.*operation:"; then
      echo "✓ EXPECTED: AWS rejected the request"
      echo "$OUTPUT" | grep "An error occurred" | head -1
      if [[ "$expect_success" == "true" ]]; then
        echo "✗ But we expected success!"
      else
        PASSED=$((PASSED + 1))
      fi
    else
      echo "✗ UNEXPECTED: command failed but NOT due to AWS error"
      echo "$OUTPUT" | tail -10
    fi
  fi
}

# 0. Normal exchange (should succeed)
run_test "normal exchange (success)" true \
  ./exchange.sh --tag User-Grant=admin --tag Group-Grant=devs

# 1. Empty source identity
run_test "empty sourceIdentity" false \
  env EMPTY_SOURCE_IDENTITY=1 ./exchange.sh --tag User-Grant=admin

# 2. Missing source identity
run_test "missing sourceIdentity" false \
  env SKIP_SOURCE_IDENTITY=1 ./exchange.sh --tag User-Grant=admin

# 3. Wrong tag key
run_test "wrong tagKey (ShouldNotExist)" false \
  ./exchange.sh --tag ShouldNotExist=hacker

echo ""
echo "****************************************"
echo "SUMMARY: $PASSED/$TOTAL tests passed"
echo "****************************************"
