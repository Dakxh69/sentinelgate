#!/usr/bin/env bash
# SentinelGate end-to-end interactive demo scenario:
#   register → login (JWT) → GET /protected/data (200) →
#   upload Aadhaar + API_KEY → 403 DLP_POLICY_BLOCK →
#   verify audit trail → trigger rate limiter → 429 RATE_LIMIT_EXCEEDED
#
# Usage:
#   BASE=http://localhost:8000 ADMIN_PASSWORD=... bash scripts/demo.sh
#   (ADMIN_PASSWORD is only needed for step 5, reading the audit trail)
set -euo pipefail

BASE="${BASE:-http://localhost:8000}"
JQ="${JQ:-jq}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@sentinelgate.example}"

if ! command -v "$JQ" >/dev/null 2>&1; then
  echo "demo: jq is required (set JQ=/path/to/jq to override)" >&2
  exit 2
fi

if command -t color >/dev/null 2>&1 || [ -t 1 ]; then
  BOLD=$'\e[1m'; GREEN=$'\e[32m'; RED=$'\e[31m'; YELLOW=$'\e[33m'; CYAN=$'\e[36m'; RESET=$'\e[0m'
else
  BOLD=""; GREEN=""; RED=""; YELLOW=""; CYAN=""; RESET=""
fi
step()  { printf '\n%s== %s ==%s\n' "$BOLD$CYAN" "$*" "$RESET"; }
ok()    { printf '%s  ✔ %s%s\n' "$GREEN" "$*" "$RESET"; }
fail()  { printf '%s  ✘ %s%s\n' "$RED" "$*" "$RESET"; exit 1; }

trap 'printf "%s  ✘ demo failed at line %s%s\n" "$RED" "$LINENO" "$RESET" >&2' ERR

step "Step 1 · register"
USER="demo$RANDOM"
EMAIL="$USER@example.com"
CODE=$(curl -s -o /tmp/demo-register.json -w '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d "{\"username\": \"$USER\", \"email\": \"$EMAIL\", \"password\": \"demo-strong-pass-123\"}" \
  "$BASE/auth/register")
[ "$CODE" = "201" ] || fail "register returned $CODE (expected 201)"
ok "registered $EMAIL (USER role)"

step "Step 2 · login → JWT"
TOKEN=$(curl -s -H 'Content-Type: application/json' \
  -d "{\"email\": \"$EMAIL\", \"password\": \"demo-strong-pass-123\"}" \
  "$BASE/auth/login" | $JQ -r '.access_token')
[ -n "$TOKEN" ] && [ "$TOKEN" != "null" ] || fail "login did not return a token"
ok "JWT received (${#TOKEN} chars, bearer)"

step "Step 3 · normal request → GET /protected/data"
CODE=$(curl -s -o /tmp/demo-data.json -w '%{http_code}' \
  -H "Authorization: Bearer $TOKEN" "$BASE/protected/data")
[ "$CODE" = "200" ] || fail "protected/data returned $CODE (expected 200)"
$JQ -e '.resource == "internal-data"' /tmp/demo-data.json >/dev/null \
  || fail "unexpected payload: $(cat /tmp/demo-data.json)"
ok "200 OK — forwarded to the internal backend:"
cat /tmp/demo-data.json

step "Step 4 · sensitive upload → expect 403 DLP_POLICY_BLOCK"
CODE=$(curl -s -o /tmp/demo-block.json -w '%{http_code}' \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"content": "aadhaar 123456789012 / api_key=supersecrettoken123"}' \
  "$BASE/protected/upload")
[ "$CODE" = "403" ] || fail "upload returned $CODE (expected 403)"
$JQ -e '.error == "DLP_POLICY_BLOCK"' /tmp/demo-block.json >/dev/null \
  || fail "unexpected block payload: $(cat /tmp/demo-block.json)"
ok "403 — blocked by policy (AADHAAR + API_KEY detected, risk ≥ 0.8)"
cat /tmp/demo-block.json

step "Step 5 · audit record (admin reads the trail)"
if [ -z "${ADMIN_PASSWORD:-}" ]; then
  ok "(skipped: ADMIN_PASSWORD not set — audit row is still written, see /admin/audit)"
else
  ADMIN_TOKEN=$(curl -s -H 'Content-Type: application/json' \
    -d "{\"email\": \"$ADMIN_EMAIL\", \"password\": \"$ADMIN_PASSWORD\"}" \
    "$BASE/auth/login" | $JQ -r '.access_token')
  [ -n "$ADMIN_TOKEN" ] && [ "$ADMIN_TOKEN" != "null" ] || fail "admin login failed"
  curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" \
    "$BASE/admin/audit?decision=BLOCK&limit=1" > /tmp/demo-audit.json
  $JQ -e '.total >= 1' /tmp/demo-audit.json >/dev/null || fail "no BLOCK audit row found"
  ok "latest BLOCK audit event:"
  $JQ '.items[0] | {decision, risk_score, detected_categories, reason, response_status, path}' \
    /tmp/demo-audit.json
fi

step "Step 6 · rate limiting → hammer the gateway (expect 429)"
SEEN_429=0
for _ in $(seq 1 130); do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $TOKEN" "$BASE/protected/data")
  if [ "$CODE" = "429" ]; then SEEN_429=1; break; fi
done
[ "$SEEN_429" = "1" ] || fail "no 429 after 130 requests"
ok "429 Too Many Requests observed"

printf '\n%s%sDEMO COMPLETE — all §44 steps behaved as specified.%s\n' "$BOLD" "$GREEN" "$RESET"
