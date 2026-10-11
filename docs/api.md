# SentinelGate — API Reference

Gateway base URL: `http://localhost:8000` (the only published port).
Every response carries an `X-Request-ID` header (§33): the incoming value is
honored only if it matches `^[A-Za-z0-9._-]{8,64}$`, otherwise a fresh
`uuid4().hex` is generated and echoed. Interactive OpenAPI: `/docs`.

All evaluation errors use the uniform shape (§32):

``` json
{"error": "ERROR_CODE", "message": "..."}
```

No stack traces are ever returned to clients; details go to server logs only.

---

## Authentication

### `POST /auth/register` → 201

``` bash
curl -s -X POST localhost:8000/auth/register -H 'Content-Type: application/json' \
  -d '{"username":"daksh","email":"daksh@example.com","password":"strong-password"}'
```

``` json
{"id": 7, "username": "daksh", "email": "daksh@example.com",
 "role": "USER", "created_at": "2026-10-11T06:00:00", "is_active": true}
```

Validation: username 3–32 chars, valid email (EmailStr), password ≥ 8 chars
(mismatch → 422 `INVALID_REQUEST`). Duplicate email **or** username → 409
`INVALID_REQUEST`. Default role USER (§7).

### `POST /auth/login` → 200

``` bash
curl -s -X POST localhost:8000/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"daksh@example.com","password":"strong-password"}'
```

``` json
{"access_token": "<JWT>", "token_type": "bearer"}
```

JWT claims: `sub` (user id), `role`, `iat`, `exp` (HS256,
`JWT_EXPIRATION_MINUTES`, default 30). Never any secret material (§8).
Any failure (unknown email, wrong password, deactivated) → the same
**401 `AUTHENTICATION_FAILED`** — deliberately indistinguishable,
no user enumeration. Outcomes are audited.

Both `/auth/*` endpoints are guarded by a per-IP fixed-window rate limiter
(brute-force mitigation, §36) — same 429 semantics as below.

## Protected (pipeline enforced)

All three need `Authorization: Bearer <token>`; missing/bad → 401.

### `GET /protected/profile` → 200

Caller's own record (gateway-owned, outside the DLP pipeline by design).
Allowed for USER/GUEST/ADMIN.

``` json
{"id": 7, "username": "daksh", "email": "daksh@example.com",
 "role": "USER", "created_at": "...", "is_active": true}
```

### `GET /protected/data`

USER/ADMIN only (GUEST → 403 `AUTHORIZATION_FAILED`). Runs the full §6
pipeline. ALLOW → forwards to the internal backend:

``` bash
curl -s localhost:8000/protected/data -H "Authorization: Bearer $TOKEN"
```

``` json
{
  "resource": "internal-data",
  "served_for": "7", "role": "USER", "request_id": "…",
  "items": ["alpha", "beta", "gamma"],
  "stage": "forwarded"
}
```

### `POST /protected/upload`

USER/ADMIN only; runs the pipeline with the `external_upload` risk modifier
(+0.20). Any sensitive detection by the seeded USER policy → 403:

``` json
{"error": "DLP_POLICY_BLOCK", "message": "Request blocked by DLP policy"}
```

RESPONSE schema for ALLOW includes the §15 DLP contract plus the risk:

``` json
{
  "detected": true, "matches": [{"type": "EMAIL", "confidence": 0.9}],
  "risk_score": 0.3, "stage": "forwarded", "…backend keys…": "…"
}
```

## Admin (ADMIN only → otherwise 403 `AUTHORIZATION_FAILED`)

### `GET /admin/policies` → 200

``` json
{"policies": [{"id": 1, "name": "baseline-allow", "role": null,
  "path_pattern": "/*", "http_method": null, "sensitive_required": false,
  "minimum_risk": 0.0, "action": "ALLOW", "enabled": true, "created_at": "…"}]}
```

### `POST /admin/policies` → 201 · `PUT /admin/policies/{id}` → 200 ·
### `DELETE /admin/policies/{id}` → 204

Body (create/update, §21 columns):

``` json
{"name": "block-user-upload-sensitive", "role": "USER",
 "path_pattern": "/protected/upload", "http_method": null,
 "sensitive_required": true, "minimum_risk": 0.8, "action": "BLOCK",
 "enabled": true}
```

Validation fails closed (§35.7): invalid values → 422 `INVALID_REQUEST`,
**never** defaulted to ALLOW. `action ∈ {ALLOW,BLOCK,REVIEW}`;
`minimum_risk ∈ [0.0,1.0]`; `role ∈ {ADMIN,USER,GUEST}` or null;
`path_pattern` starts with `/`. Unknown id on PUT/DELETE → 404
`POLICY_NOT_FOUND`.

### `GET /admin/audit` → 200

Paginated audit events, newest first. Query params:
`decision`, `user_id`, `path_prefix`, `limit` (1–200, default 50), `offset`.

``` json
{"items": [{"id": 42, "request_id": "…", "timestamp": "…",
  "user_id": 7, "role": "USER", "source_ip": "172.18.0.1",
  "method": "POST", "path": "/protected/upload", "decision": "BLOCK",
  "risk_score": 1.0, "detected_categories": ["AADHAAR", "API_KEY"],
  "reason": "block-user-upload-sensitive", "response_status": 403}],
 "total": 314, "limit": 50, "offset": 0}
```

## Health

### `GET /health` → 200 or 503

``` json
{"status": "ok", "checks": {"postgres": "ok", "redis": "ok"}}
```

Any failing dependency → 503 with `status: "degraded"`, the failing check
named, and `error: "SERVICE_UNAVAILABLE"`.

---

## Error code catalog (§32)

| Code | HTTP | When |
|---|---|---|
| `AUTHENTICATION_FAILED` | 401 | missing/bad bearer token, bad credentials, deactivated user, JWT decode failure |
| `AUTHORIZATION_FAILED` | 403 | authenticated role not permitted (RBAC) |
| `RATE_LIMIT_EXCEEDED` | 429 | window counter above the limit (per-user everywhere; per-IP on /auth/*) |
| `INVALID_REQUEST` | 422 | body validation failure; also 409 duplicate-registration payload shape |
| `INTERNAL_SECURITY_ERROR` | 500 | unexpected failure in a security stage — Redis outage, policy-engine error, DLP engine failure (audited with distinct reasons: `REDIS_UNAVAILABLE`, `POLICY_ENGINE_ERROR`, `DLP_ENGINE_FAILURE`) |
| `DLP_POLICY_BLOCK` | 403 | policy decision BLOCK (sensitive data / risk over minimum) |
| `BACKEND_UNAVAILABLE` | 502 | internal backend unreachable/timed out (availability, not security) |
| `SERVICE_UNAVAILABLE` | 503 | `/health` dependency failure |
| `POLICY_NOT_FOUND` | 404 | PUT/DELETE on unknown policy id |

## Audit event fields (§20)

`id` · `request_id` · `timestamp` · `user_id` · `role` · `source_ip` ·
`method` · `path` · `decision` (`ALLOW`/`BLOCK`/`REVIEW`) · `risk_score` ·
`detected_categories` (JSONB list of category names — **never raw values**) ·
`reason` (rule name or failure code) · `response_status`.

Never stored/logged: passwords, JWTs, full API keys, full card/Aadhaar
numbers, raw Authorization header (§20, §35.5).

## Rate-limit semantics (§12)

- Fixed window: `window = epoch_seconds // RATE_LIMIT_WINDOW_SECONDS`;
  key `rate_limit:{user_id}:{window}` (INCR + EXPIRE window+1).
- **Boundary:** `count <= limit` is allowed (with default 100, request #100
  is the last allowed, #101 gets 429) — tested explicitly.
- Shared state in Redis, not process memory, so it stays consistent across
  gateway instances.
- Fail closed: Redis error → 503 `INTERNAL_SECURITY_ERROR` (never an allow).

## REVIEW = 202 rationale (§17–19)

REVIEW is a *decision*, not an error: the request is **held, not processed**
(nothing is forwarded), so a success-family status (202 Accepted) is used
while the audit trail records `decision="REVIEW"` separately from BLOCK.
This lets downstream tooling (a review queue) distinguish "blocked with
 prejudice" from "quarantined for human review".
