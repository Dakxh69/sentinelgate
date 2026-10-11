#!/usr/bin/env bash
# End-to-end smoke test against the Docker Compose stack.
#
# Prerequisite: docker compose up --build -d   (gateway published on :8000)
# Flow: register → login → protected call (allowed, forwarded to backend) →
# sensitive upload (blocked 403) → audit rows as admin → rate limiting (429).
set -euo pipefail

BASE="${BASE:-http://localhost:8000}"
JQ="${JQ:-jq}"

say() { printf '\n== %s\n' "$*"; }

trap 'say "FAILED (line $LINENO)"; exit 1' ERR

say "health check (gateway :8000 must be up)"
curl -sf "$BASE/health" | $JQ -e '.status == "ok"' >/dev/null

say "register demo user"
USER_EMAIL="e2e-$RANDOM@example.com"
REGISTER_CODE=$(curl -s -o /tmp/e2e-register.json -w '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d "{\"username\": \"e2euser$RANDOM\", \"email\": \"$USER_EMAIL\", \"password\": \"e2e-strong-password\"}" \
  "$BASE/auth/register")
echo "register -> $REGISTER_CODE"
case "$REGISTER_CODE" in 201|409) ;; *) echo "unexpected register status"; exit 1;; esac

say "login"
TOKEN=$(curl -s -H 'Content-Type: application/json' \
  -d "{\"email\": \"$USER_EMAIL\", \"password\": \"e2e-strong-password\"}" \
  "$BASE/auth/login" | $JQ -r '.access_token')
[ -n "$TOKEN" ] && [ "$TOKEN" != "null" ]

say "GET /protected/data (expect 200 forwarded from internal backend)"
DATA_CODE=$(curl -s -o /tmp/e2e-data.json -w '%{http_code}' \
  -H "Authorization: Bearer $TOKEN" "$BASE/protected/data")
echo "data -> $DATA_CODE"
[ "$DATA_CODE" = "200" ]
$JQ -e '.resource == "internal-data"' /tmp/e2e-data.json >/dev/null

say "POST /protected/upload with Aadhaar + API key (expect 403 DLP_POLICY_BLOCK)"
BLOCK_CODE=$(curl -s -o /tmp/e2e-block.json -w '%{http_code}' \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"aadhaar": "aadhaar 234123412345", "api_key": "api_key=supersecrettoken123"}' \
  "$BASE/protected/upload")
echo "block -> $BLOCK_CODE"
[ "$BLOCK_CODE" = "403" ]
$JQ -e '.error == "DLP_POLICY_BLOCK"' /tmp/e2e-block.json >/dev/null

say "internal routes are NOT reachable through the gateway (expect 404)"
INTERNAL_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/internal/data")
echo "internal -> $INTERNAL_CODE"
[ "$INTERNAL_CODE" = "404" ]

say "login as seeded admin (ADMIN_PASSWORD from .env) to read the audit trail"
ADMIN_TOKEN=$(curl -s -H 'Content-Type: application/json' \
  -d "{\"email\": \"admin@sentinelgate.example\", \"password\": \"${ADMIN_PASSWORD:?export ADMIN_PASSWORD}\"}" \
  "$BASE/auth/login" | $JQ -r '.access_token')
curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$BASE/admin/audit?limit=10" | $JQ -e '.total >= 1' >/dev/null
echo "audit rows visible: OK"

say "rate limiting: hammer the gateway (expect 429 eventually)"
SEEN_429=0
for _ in $(seq 1 130); do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$BASE/protected/data")
  if [ "$CODE" = "429" ]; then SEEN_429=1; break; fi
done
[ "$SEEN_429" = "1" ]
echo "429 observed: OK"

say "ALL E2E CHECKS PASSED"
