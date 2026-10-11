# SentinelGate — Architecture

Companion to the spec (§3/§6/§21/§28/§29/§46). This document describes what
is *actually implemented*, not aspirations (spec §2.3).

## 1. Component diagram (§3)

``` text
                         CLIENT
                           |  HTTP
                           v
                +---------------------------+
                |        SentinelGate       |
                |  (gateway, FastAPI :8000) |
                |                           |
                |  RequestContextMiddleware |  request IDs + context
                |           |               |
                |  Request Validation       |
                |  JWT Authentication       |  PyJWT HS256 + argon2 users
                |  RBAC Authorization       |
                |  Rate Limiter             |  Redis fixed window
                |  DLP Engine               |  Python scanner (+ C++ engine
                |                           |   via subprocess when
                |                           |   DLP_ENGINE_PATH set)
                |  Risk Scoring             |  category weights + modifiers
                |  Policy Engine            |  policies table, most-restrictive
                |  ALLOW / BLOCK / REVIEW   |
                +------------+--------------+
                             |
        +--------------------+----------------------+
        |                                           |
     ALLOW                                      BLOCK / REVIEW
        |                                           |
        v                                           v
+--------------------+                     +------------------+
| Protected Backend  |                     |  Audit Database  |
| app.internal.main  |                     |  PostgreSQL      |
| :8001, internal    |                     |  audit_events    |
| only (§27/§29)     |                     +------------------+
+--------------------+

Supporting:  PostgreSQL (users, policies, audit_events) · Redis (rate-limit
counters, security_events:{ip}) · Docker (reproducible isolated deployment)
```

## 2. Pipeline flow (§6) — as implemented

Implemented in `backend/app/services/gateway_service.py` as one explicit
ordered function (`handle_protected`) with a `StageRecorder` that a
dedicated test asserts as the exact sequence:

``` text
authentication → authorization → rate_limiting →
dlp_inspection → risk_scoring → policy_evaluation →
(BLOCK/REVIEW: stop) → forward_to_backend → audit
```

Implementation notes:

- **Authentication/authorization** run as FastAPI dependencies
  (`get_current_user`, `require_role`) *before* `handle_protected`; the stage
  recorder marks them at pipeline entry so the §6 sequence stays observable.
- **Rate limiting** (`enforce_user_rate_limit_raw`) audits and raises
  `SentinelGateError` on over-limit (429) or Redis failure (503
  `INTERNAL_SECURITY_ERROR`, audit reason `REDIS_UNAVAILABLE`) — the pipeline
  short-circuits and renders the limiter's error.
- **DLP + risk**: body (stringified JSON / form / text) and query string are
  scanned; oversized (> 1 MiB) bodies are flagged `unscanned`; the
  `Authorization` header is never scanned. Any engine failure is audited
  (`DLP_ENGINE_FAILURE`) and becomes 500.
- **Policy evaluation** reads the stashed DLP/risk results, evaluates the
  policies table (most restrictive wins; no matching rule + sensitive →
  BLOCK), writes the decision audit row, then returns/enforces the decision:
  BLOCK → `403 DLP_POLICY_BLOCK`, REVIEW → `202 held`, ALLOW → falls through.
- **BLOCK/REVIEW short-circuit before forwarding** (asserted by the
  stage-order test: the recorded sequence never contains
  `forward_to_backend` for a blocked flow).
- **Forwarding** happens only for ALLOW on the route
  table (`GET /protected/data` → `GET /internal/data`,
  `POST /protected/upload` → `POST /internal/upload`) via httpx with a 5 s
  timeout. `/protected/profile` is gateway-owned (no forward entry) and
  stays outside the pipeline by design (Day 2).
- **Audit is always written** — for ALLOW (after forwarding succeeds),
  BLOCK, REVIEW, and every rejection, covering rate-limit and backend-down
  (`502 BACKEND_UNAVAILABLE`, availability — deliberately distinct from
  security failures).

## 3. Gateway vs backend responsibilities (§28)

| Gateway owns | Backend owns |
|---|---|
| authentication (JWT) | business logic responses |
| authorization (RBAC) | data payload (`/internal/data`) |
| rate limiting (Redis) | upload byte accounting (`/internal/upload`) |
| DLP inspection | liveness probe (`/internal/health`) |
| risk scoring | |
| policy evaluation | |
| audit logging | |

The backend deliberately contains **no** security logic (no JWT check, no
RBAC, no DLP) — it trusts the sanitized identity headers the gateway
forwards: only `X-Request-ID`, `X-User-Id`, `X-User-Role` (§28 least
privilege). `Authorization` and arbitrary client headers never cross.

## 4. Data stores (§21)

**PostgreSQL** — three tables (created by Alembic migrations, populated by
the seed script):

- `users` — id (BIGSERIAL), username (unique), email (unique), argon2id
  `password_hash`, role (`ADMIN`/`USER`/`GUEST`), created_at, is_active
- `policies` — id, name, nullable role / path_pattern / http_method /
  sensitive_required / minimum_risk, action (`ALLOW`/`BLOCK`/`REVIEW`),
  enabled, created_at
- `audit_events` — id, request_id (NOT NULL), timestamp, nullable user_id /
  role / source_ip / method / path / decision / risk_score /
  detected_categories (**JSONB on PostgreSQL**) / reason / response_status

**Redis** — two key families (both TTL-bounded, never process memory):

- `rate_limit:{user_id}:{window}` — per-user fixed window (§12);
  `rate_limit:ip:{source_ip}:{window}` — per-IP window guarding `/auth/*`
  (brute-force mitigation, §36). Window = `epoch // 60` (default), INCR +
  EXPIRE window+1, `count <= limit` allowed, over → 429.
- `security_events:{source_ip}` — incremented (best-effort) on every
  401/403/429 audit write, TTL 600 s; read by the risk engine as the
  `suspicious_behavior` modifier when ≥ 5 (§16).

## 5. Decision matrix

| Decision | HTTP | Body | Forwarded? | Audited? |
|---|---|---|---|---|
| ALLOW | backend status (200) | backend payload + DLP matches + `risk_score` + `stage:"forwarded"` | yes | yes (ALLOW) |
| REVIEW | 202 | `{"decision":"REVIEW","reason":"Request held for review by DLP policy"}` | **no** | yes |
| BLOCK (policy) | 403 | `{"error":"DLP_POLICY_BLOCK", ...}` | **no** | yes (decision/risk/categories/reason) |
| REVIEW semantics | REVIEW means *held for review*, not processed: the request stops at the gateway like a BLOCK, but is distinguishable in audit (`decision="REVIEW"`). Admin-created REVIEW policies make this the enforcement result; audit rows feed the review queue story. |

Rejection/availability codes (§32): 401 `AUTHENTICATION_FAILED`,
403 `AUTHORIZATION_FAILED`, 429 `RATE_LIMIT_EXCEEDED`,
422 `INVALID_REQUEST`, 500 `INTERNAL_SECURITY_ERROR` (Redis down, policy
error, DLP engine failure — all audited with distinct reasons), 502
`BACKEND_UNAVAILABLE`, 503 `SERVICE_UNAVAILABLE` (health).

## 6. Scaling discussion (§46, as implemented)

- **What happens if Redis goes down?** The rate limiter fails closed:
  INCR raises `RedisError` → rejection 503 `INTERNAL_SECURITY_ERROR`, audit
  reason `REDIS_UNAVAILABLE`. Never an allow. (The *risk* counter read fails
  soft to 0 — a failed read must not silently raise anyone's risk.)
- **What happens if PostgreSQL goes down?** Auth (user lookups) and policy
  (rules table) fail → requests reject; audit writes are best-effort and
  never flip a decision. `/health` returns 503 with the failing check named.
- **Horizontal scaling:** counters live in Redis (shared state), so fixed
  windows are already consistent across gateway instances — the spec's own
  test for the same idea holds here. Stateless gateway replicas can be
  added behind a load balancer today; sessions live in the JWT, not memory.
  Scaling further needs a shared Redis/PostgreSQL tier sized accordingly.
- **Rate limiting under distribution:** the fixed window is key-per-user /
  per-IP in Redis, which is the simple distributed answer; a production
  evolution would slide windows or shard counters (future work §47).
- **Protecting secrets:** no secrets in logs (redaction denylist + never
  logging Authorization/bodies), JWT_SECRET passed via env only, seed
  passwords via env only, `.env` never committed.
- **DLP engine failure:** subprocess non-zero exit / timeout / malformed
  output → fail closed 500 with audited `DLP_ENGINE_FAILURE`; output is
  validated before use.
