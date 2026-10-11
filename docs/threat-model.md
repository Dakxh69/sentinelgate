# SentinelGate — Threat Model (§36)

Scope: the SentinelGate gateway, its internal demo backend, and the data
stores (PostgreSQL, Redis). Persona: an intern-level reviewer should be able
to follow every mitigation to code. This documents *implemented* mitigations
plus honest residual risks — nothing is claimed without an implementation.

---

## T1 — Brute force (§36)

**Threat:** attacker sends many login attempts against `/auth/login`
(credential stuffing / password guessing).

**Mitigation (implemented):**
- Per-IP fixed-window rate limiter on both `/auth/*` endpoints
  (`enforce_ip_rate_limit`, `rate_limit:ip:{ip}:{window}` in Redis).
- Per-user fixed-window limiter on every protected route (default 100/60 s).
- Failed logins are audited and also increment `security_events:{ip}`
  (TTL 600 s) — which feeds the risk engine's `suspicious_behavior` modifier
  (+0.10) for subsequent requests from that IP.
- Uniform 401 `AUTHENTICATION_FAILED` with no user-enumeration hints.

**Residual risk:** a fixed window allows ~2× the threshold around a window
boundary (documented in README §17); a distributed attacker rotating IPs
defeats the per-IP limiter (per-account lockout/throttling would be the next
layer, future work).

## T2 — Stolen JWT (§36)

**Threat:** attacker obtains a valid bearer token (leaked header, log, referer).

**Mitigation (implemented):**
- Short expiration: 30 minutes by default (`JWT_EXPIRATION_MINUTES`).
- Full validation on every request: signature (HS256), expiry, `sub`
  resolution against the users table, `is_active` check — a deactivated
  account's token stops working immediately.
- Token values are never logged; the redaction denylist also rewrites any
  bearer-shaped value (`Bearer …`, `eyJ…`) that appears under an innocuous
  key (`app/core/logging.py`).

**Residual risk:** no revocation list — a token stolen mid-lifetime remains
usable until expiry in a single-node deployment; HTTPS is required in any
real deployment (termination is deployment config, not implemented in this
repo, which serves plain HTTP for local demonstration).

## T3 — Privilege escalation (§36)

**Threat:** a USER (or GUEST) attempts ADMIN operations, or reaches
admin-only data.

**Mitigation (implemented):**
- RBAC dependency (`require_role(ADMIN)`) on every admin route — 403
  `AUTHORIZATION_FAILED`, audited (`record_authz_event`).
- Role pre-checks on protected routes (`require_role(USER, ADMIN)`): GUEST →
  403 before the pipeline runs.
- Policy engine is role-aware and most-restrictive-wins
  (`BLOCK > REVIEW > ALLOW`); seeded policies block USER sensitive uploads
  and hold ADMIN ones for review.
- Tested: USER/GUEST/ADMIN matrix in `test_authorization.py`, and §35.3 in
  `test_security.py`.

**Residual risk:** no per-object permissions or fine-grained scopes —
roles are coarse (ADMIN/USER/GUEST); policy rules add path/method/risk
nuance but remain the same three actions.

## T4 — Data exfiltration (§36)

**Threat:** user uploads/posts sensitive data (Aadhaar, card, keys…) to move
it out of a controlled environment.

**Mitigation (implemented):**
- DLP inspection of every request body + query string on the pipeline
  routes: seven categories with false-positive guards (context windows for
  bare Indian phone/Aadhaar numbers; Luhn for cards; value-length minimum
  for `api_key=…`).
- The C++ Aho-Corasick engine adds a fast keyword layer when
  `DLP_ENGINE_PATH` is configured (Docker does).
- Risk scoring (weights + upload modifier + suspicious-behavior modifier,
  capped at 1.0) turns detections into a policy input.
- Policy enforcement: seeded USER policy blocks sensitive uploads
  (minimum risk 0.5) → 403 `DLP_POLICY_BLOCK`; nothing is forwarded.
- Oversized bodies (> 1 MiB) are not scanned but flagged `unscanned` and
  **treated as sensitive** by the policy layer — truncation cannot be used
  to smuggle data through (fail closed).
- Audit rows record only category names — the data itself is never
  persisted into the audit trail.

**Residual risk:** regex/heuristic detection is not production PII
classification (README §17): base64-encoded, encrypted, translated, or
renamed sensitive data passes context-free scanning; only the seven
categories are covered.

## T5 — Secret leakage through logs (§36)

**Threat:** the application logs passwords, tokens, API keys, or the raw
values DLP matched.

**Mitigation (implemented):**
- Structured `key=value` logging with a **redaction denylist** (`password`,
  `token`, `access_token`, `api_key`, `apikey`, `secret`, `authorization`,
  `card`, `aadhaar`, `uid`, `private_key`) applied recursively — denial
  happens even if a caller passes a sensitive field by mistake.
- Bearer-shaped values redacted anywhere they appear.
- Raw request bodies and the `Authorization` header are never logged at all;
  the request-context middleware explicitly never reads Authorization.
- Audit events carry metadata (decision, categories, reason), never matched
  secret values (§20); DLP public results are type + confidence only (§15).
- Tested: §35.5 (no sensitive data in audit), plus log-redaction tests in
  `test_security.py`.

**Residual risk:** the denylist is key-based and pattern-assisted; a
sensitive value under an unexpected key name (e.g. `note: "my card is
4111…"`) is only caught if a DLP category *pattern* sees it — and
application logs of ordinary business fields are not scanned.

## T6 — Backend bypass (§36)

**Threat:** attacker connects directly to the internal backend, skipping all
gateway enforcement.

**Mitigation (implemented):**
- Docker Compose topology (§29): the backend service has **no published
  ports**; only the gateway publishes `8000:8000`. The backend is reachable
  only inside the compose network — by the gateway.
- The gateway itself refuses to route `/internal/*` — any such path returns
  a plain 404, so the backend's shape is not even revealed through the
  gateway (§35.6, tested).
- Backend owns no security logic but nothing to bypass **into**:
  its routes are demo data echoing the gateway-supplied identity headers.
- Runtime-verified: direct host connection to the backend is refused;
  `/internal/data` via the gateway is 404.

**Residual risk:** only the compose deployment isolates the backend; running
`uvicorn app.internal.main:app` on an exposed host without the network
boundary voids this defense. The backend trusts `X-User-Id`/`X-User-Role`
headers, which is safe *only* behind the gateway.
