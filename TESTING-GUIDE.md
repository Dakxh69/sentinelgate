# SentinelGate — Manual Test Walkthrough & Project Guide

*Read this top to bottom once and you will be able to explain every part of
this project in an interview — then follow the numbered steps to prove the
whole system works with your own eyes. Expected outputs are written under
every command so you can cross-verify nothing was faked.*

---

## PART 1 — Understand the project (what you built)

### 1.1 The one-sentence pitch

> SentinelGate is a **Zero-Trust security gateway**: it sits between clients
> and a backend service and, before letting any request through, it
> authenticates the caller, checks their role, rate-limits them, scans their
> data for sensitive information (DLP), scores the risk, applies policies
> (ALLOW / BLOCK / REVIEW), audits everything, and only then forwards the
> request to the backend.

### 1.2 The problem it solves

Companies don't want each backend service to invent its own security. They
want **one gate** that never trusts a request by default. This project
demonstrates that idea end-to-end:

- A user with valid credentials but **sensitive data in their payload**
  (an Aadhaar number, a credit card, an API key) gets **blocked** even
  though they're logged in.
- A user can't hammer the API endlessly — **rate limits** apply.
- A normal user can't reach **admin** functions — **RBAC** applies.
- Every decision is **audited** in PostgreSQL, searchable by admins.
- If any security component breaks (Redis dies, policy engine errors,
  the C++ scanner fails), the system **rejects** the request instead of
  letting it through — this is called **"fail closed."**

### 1.3 How a request flows through the system (memorize this order)

```text
Client request
   │
   ▼
1. Request Validation  ── bad JSON/body? → 422 INVALID_REQUEST
2. JWT Authentication  ── no/decoded-bad token? → 401 AUTHENTICATION_FAILED
3. RBAC Authorization  ── wrong role? → 403 AUTHORIZATION_FAILED
4. Rate Limiting       ── over 100 req/60s? → 429 RATE_LIMIT_EXCEEDED
   │                        (Redis fixed-window counter, shared state)
   ▼
5. DLP Inspection      ── scan body + query string for:
   │                        EMAIL / PHONE / AADHAAR / CREDIT_CARD /
   │                        API_KEY / PASSWORD / SECRET
   │                        (Python registry + C++ Aho-Corasick engine)
   ▼
6. Risk Scoring        ── weights per category, capped at 1.0
   │                        upload +0.20, suspicious IP +0.10
   ▼
7. Policy Evaluation   ── match against rules in the `policies` table
   │                        conflict → most restrictive wins
   ▼
8. Decision
   ├─ BLOCK  → 403 DLP_POLICY_BLOCK (audited, NEVER forwarded)
   ├─ REVIEW → 202 held-for-review  (audited, NEVER forwarded)
   └─ ALLOW  → forward to internal backend (audited after)
   ▼
9. Audit Everything    ── every outcome lands in the audit_events table
10. Backend Response   ── only ALLOWed requests ever see the backend
```

**Interview line:** *"The pipeline order is explicit in code and asserted by
a stage-order test — a blocked request's recorded stage list never contains
`forward_to_backend`."*

### 1.4 The moving parts (and why each technology was chosen)

| Part | Technology | Why |
|---|---|---|
| Gateway API | **FastAPI + Uvicorn** | modern async Python web framework, auto OpenAPI docs |
| Database | **PostgreSQL 16** | persistent, relational store for users/policies/audit; JSONB for category lists |
| Counter store | **Redis 7** | shared, fast, TTL-friendly counter store so rate limiting works across gateway instances (not process memory) |
| Auth | **PyJWT (HS256) + Argon2id** | stateless tokens for APIs; strong modern password hashing |
| Fast scanning | **C++17 + CMake (Aho-Corasick)** | demonstrates a CPU-sensitive text-scanning component at low level; single-pass multi-pattern matching |
| Containerization | **Docker Compose** | reproducible local deployment; network isolation to keep the backend private |
| Testing | **pytest + ctest** | 164 backend tests + 1 C++ Aho-Corasick test suite |

### 1.5 Repository map (what lives where)

```text
backend/
  app/
    main.py               ← gateway FastAPI app (CORS, errors, /health)
    internal/main.py      ← demo BACKEND app (business logic only, :8001)
    api/                  ← HTTP routes (auth, protected, admin, audit, policies)
    core/                 ← config, JWT/password security, logging, Redis client
    middleware/           ← request-ID + context middleware
    models/               ← SQLAlchemy ORM: User, Policy, AuditEvent
    schemas/              ← Pydantic request/response shapes
    services/
      gateway_service.py  ← ★ THE §6 PIPELINE (exam this file first)
      auth_service.py     ← register/login logic
      dlp_service.py      ← detection pattern registry + C++ integration
      risk_service.py     ← category weights + modifiers
      policy_service.py   ← rule matching, most-restrictive-wins
      rate_limit_service.py ← Redis fixed-window limiter
      audit_service.py    ← write events, feed suspicious-behavior counter
    db/                   ← Alembic migrations + seed script
  tests/                  ← 164 pytest tests (incl. all 10 §35 security tests)

dlp-engine/               ← C++ Aho-Corasick scanner + CLI
  src/aho_corasick.cpp    ← trie + failure links (the algorithm)
  src/dlp_engine.cpp      ← scan() wrapper, default keywords
  src/main.cpp            ← `dlp-engine --scan` CLI (JSON in/out)

docs/                     ← architecture.md, api.md, threat-model.md, benchmark.md
specs/                    ← the 7-day implementation plan + status
scripts/                  ← demo.sh, verify_dod.sh, e2e_docker.sh, dev_services.sh
dashboard/app.py          ← optional read-only Streamlit dashboard (§40)
docker-compose.yml        ← gateway :8000 (only published port), backend, PG, Redis
spec.md                   ← full original specification (source of truth)
```

### 1.6 Key facts to quote in an interview

- **Pipeline fail closed:** Redis down → 429→no, actually `503 INTERNAL_SECURITY_ERROR` with audit reason `REDIS_UNAVAILABLE`; policy error → 500 `POLICY_ENGINE_ERROR`; DLP engine failure → 500 `DLP_ENGINE_FAILURE`. **Never an ALLOW.**
- **Least privilege to the backend:** the backend sees *only* `X-Request-ID`, `X-User-Id`, `X-User-Role` headers — never the raw `Authorization` header or other client headers.
- **The backend has no published Docker port** — you physically cannot reach it from the host; only the gateway (on the compose network) can.
- **Audit rows store category NAMES only** (e.g. `["AADHAAR","API_KEY"]`) — never the matched value itself. Employees' secrets never leak into logs.
- **Benchmark is real, not fabricated:** `scripts/benchmark_dlp.py` regenerates `docs/benchmark.md` on your machine. Last run: 1 MB corpus — Python regex 37.88 ms vs C++ Aho-Corasick (in-process algorithmic cost amortized over CLI spawn ~22.91 ms).
- **All 164 backend tests pass**, plus 1/1 C++ test, plus the full Docker e2e passed. `scripts/verify_dod.sh` runs a whole Definition-of-Done smoke test.

---

## PART 2 — Setup (pick ONE path)

### Path A: Docker (recommended, matches production)

```bash
cd SentinalGate
cp .env.example .env
# edit .env — set these to strong values:
#   JWT_SECRET=<python -c "import secrets; print(secrets.token_urlsafe(48))">
#   POSTGRES_PASSWORD=<something>
#   ADMIN_PASSWORD=<something>
#   SEED_USER_PASSWORD=<something>
docker compose up --build -d
docker compose ps
```

**Desired output of `docker compose ps`:**

```text
NAME                        SERVICE    STATUS
sentinalgate-backend-1      backend    running (healthy)
sentinalgate-gateway-1      gateway    running (healthy)
sentinalgate-postgres-1     postgres   running (healthy)
sentinalgate-redis-1        redis      running (healthy)
```

You will also see a note that **only the gateway has a published port** —
the backend lives inside the compose network on `:8001` but has NO
`ports:` entry, and you can prove that (`curl localhost:8001` → refused).

> Skip 2.1 (which builds a local venv) and jump to **PART 3**.

### Path B: Local Python (no Docker, fastest iteration)

You need PostgreSQL + Redis reachable first. Two options:

- If you already have system PostgreSQL/Redis running → just point `.env`
  at them (port 5432 / 6379).
- On this specific dev box only, there's `scripts/dev_services.sh` to run
  local Postgres 16 + Redis 7 without Docker:

  ```bash
  scripts/dev_services.sh start
  # postgres: RUNNING (127.0.0.1:5432, ...)
  # redis:    RUNNING (127.0.0.1:6379, ...)
  ```

Then:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt

cp .env.example .env
# edit .env as above; make sure DATABASE_URL points to your Postgres
#   e.g. postgresql+psycopg://postgres:pw@127.0.0.1:5432/sentinelgate
#   and REDIS_URL=redis://127.0.0.1:6379/0

cd backend
export $(grep -v '^#' ../.env | xargs)   # load env vars

# migrate + seed
alembic upgrade head
#    desired output (last lines):
#    INFO  [alembic.runtime.migration] Will assume transactional DDL.
#    INFO  [alembic.runtime.migration] Running upgrade  -> 0001_initial, initial schema: users, policies, audit_events
python -m app.db.seed
#    desired output:
#    seed complete: 2 user(s) created, 3 policy/policies created

# run gateway (:8000)
uvicorn app.main:app --host 127.0.0.1 --port 8000
#    desired output (last lines):
#    INFO cors disabled (CORS_ALLOWED_ORIGINS empty, section 35)
#    INFO:     Application startup complete.
#    INFO:     Uvicorn running on http://127.0.0.1:8000

# in a SECOND terminal, run internal backend (:8001)
cd backend
uvicorn app.internal.main:app --host 127.0.0.1 --port 8001
#    desired output:
#    INFO:     Uvicorn running on http://127.0.0.1:8001
```

> In local-dev the gateway needs `BACKEND_URL=http://127.0.0.1:8001`
> in `.env` (the default `http://backend:8001` is the Docker-only
> hostname — with the wrong value you'll see `502 BACKEND_UNAVAILABLE`
> in Step 3; that's actually a *correct* fail-closed behavior, just
> pointed at the wrong place).

---

## PART 3 — Manual test walkthrough (10 steps)

Run every `curl` from a third terminal (leave the two services running).
`BASE=http://localhost:8000`; replace placeholders as noted.

### Step 0 — Health check

```bash
curl -s localhost:8000/health
```

**Desired output:**

```json
{"status":"ok","checks":{"postgres":"ok","redis":"ok"}}
```

✅ *What this proves:* the gateway is alive, both dependencies reachable.
The health endpoint is fail-open by design for *liveness* (it reports
status) but returns HTTP 503 if either dep is down — try killing Redis
temporarily in local-dev and you'll get `{"status":"degraded",...}` with
503. (Skip if not desired; not part of the 10 steps.)

### Step 1 — Register a user (201)

```bash
curl -s -i -X POST localhost:8000/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"daksh","email":"daksh@example.com","password":"strong-password"}'
```

**Desired output (last line):**

```json
{"id":3,"username":"daksh","email":"daksh@example.com","role":"USER","created_at":"2026-10-11T12:31:20","is_active":true}
```

The HTTP status line should say **`201 Created`**.

✅ *Proves:* registration works; role defaults to USER; password was
stored as an Argon2 hash (never plaintext — verified by test §35.1).

Now try a duplicate:

```bash
curl -s -i -X POST localhost:8000/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"daksh","email":"daksh@example.com","password":"strong-password"}'
```

**Desired output:** HTTP **409 Conflict**, body like
`{"detail":{"error":"INVALID_REQUEST","message":"Email already registered"}}`.
✅ *Proves:* uniqueness enforcement.

### Step 2 — Login (JWT) + wrong password (401)

```bash
curl -s -X POST localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"daksh@example.com","password":"strong-password"}'
```

**Desired output:**

```json
{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9....","token_type":"bearer"}
```

Save it:

```bash
TOKEN=<paste-the-token-here>   # or use: TOKEN=$(... | jq -r .access_token)
```

Then wrong password:

```bash
curl -s -i -X POST localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"daksh@example.com","password":"wrong"}'
```

**Desired output:** HTTP **401**, body
`{"error":"AUTHENTICATION_FAILED","message":"Invalid credentials"}`.

✅ *Proves:* credential verification; uniform 401 (no enumeration hints
— wrong-user and wrong-password look identical).

### Step 3 — Normal request reaches the backend (200 + forwarded)

```bash
curl -s localhost:8000/protected/data -H "Authorization: Bearer $TOKEN"
```

**Desired output:**

```json
{"detected":false,"matches":[],"risk_score":0,"resource":"internal-data","served_for":"3","role":"USER","request_id":"83a9…","items":["alpha","beta","gamma"],"stage":"forwarded"}
```

✅ *Proves:* JWT works, RBAC passed, rate limiter counted (not blocked yet),
DLP found nothing, policy `baseline-allow` matched, the pipeline reached
the **internal backend** (that's why `resource`, `items`, `stage:"forwarded"`
appear), and everything was audited.
Note `served_for:"3"` = your user id, which arrived via the sanitized
`X-User-Id` header the gateway injected — the raw Authorization header
never crossed.

### Step 4 — Sensitive upload is BLOCKED (403)

```bash
curl -s -i -X POST localhost:8000/protected/upload \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"content":"aadhaar 123456789012 api_key=supersecrettoken123"}'
```

**Desired output (last line, HTTP status 403):**

```json
{"error":"DLP_POLICY_BLOCK","message":"Request blocked by DLP policy"}
```

✅ *Proves:* DLP caught `AADHAAR` (12-digit) + `API_KEY`
(`api_key=supersecrettoken123`), risk hit 1.0 (0.90+0.90 capped),
policy `block-user-upload-sensitive` (USER + sensitive → BLOCK) fired and
the request was **never forwarded** — the backend saw nothing.

### Step 5 — The audit row exists, readable by an ADMIN only

Login as the seeded admin (password from your `.env` `ADMIN_PASSWORD`):

```bash
ADMIN_TOKEN=$(curl -s -X POST localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"admin@sentinelgate.example\",\"password\":\"$ADMIN_PASSWORD\"}" \
  | jq -r .access_token)

curl -s "localhost:8000/admin/audit?decision=BLOCK&limit=1" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq
```

**Desired output (top of the items list):**

```json
{
  "items": [
    {
      "id": 216,
      "request_id": "…",
      "user_id": 3,
      "role": "USER",
      "method": "POST",
      "path": "/protected/upload",
      "decision": "BLOCK",
      "risk_score": 1.0,
      "detected_categories": ["AADHAAR", "API_KEY"],
      "reason": "block-user-upload-sensitive",
      "response_status": 403
    }
  ],
  "total": 1
}
```

✅ *Proves:* audit persistence matches spec §20, and only category NAMES
plus the rule name were stored — **no secret values anywhere**.

Now confirm a normal USER **cannot** read the audit log:

```bash
curl -s -i localhost:8000/admin/audit -H "Authorization: Bearer $TOKEN"
```

**Desired output:** HTTP **403** with
`{"detail":"Authorization failed"}`-style body containing
`"Authorization failed"` and code `AUTHORIZATION_FAILED`.
✅ *Proves:* RBAC enforcement (§35.3).

### Step 6 — Admin policy CRUD works

```bash
curl -s -X POST localhost:8000/admin/policies \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"demo-review-user-data","role":"USER","path_pattern":"/protected/data","sensitive_required":false,"minimum_risk":null,"action":"REVIEW","enabled":true}'
```

**Desired output:**

```json
{"id":4,"name":"demo-review-user-data","role":"USER","path_pattern":"/protected/data","http_method":null,"sensitive_required":false,"minimum_risk":null,"action":"REVIEW","enabled":true}
```

(201 Created)

Invalid values must fail closed:

```bash
curl -s -i -X POST localhost:8000/admin/policies \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"bad","action":"WHATEVER"}'
```

**Desired output:** HTTP **422**, error `INVALID_REQUEST`.
✅ *Proves:* §35.7 — invalid policy config is never silently defaulted to
allow/anything; it's rejected.

### Step 7 — A REVIEW decision fires (202)

Because you just created a "REVIEW /protected/data for USER" rule in
Step 6, re-run the data call:

```bash
curl -s -i localhost:8000/protected/data -H "Authorization: Bearer $TOKEN"
```

**Desired output:**

```text
HTTP/1.1 202 Accepted
{"decision":"REVIEW","reason":"Request held for review by DLP policy"}
```

✅ *Proves:* all three decision types work; and note the backend was
**not** reached — REVIEW holds, never forwards.

Now DELETE that demo policy to restore the earlier behavior:

```bash
curl -s -i -X DELETE localhost:8000/admin/policies/4 -H "Authorization: Bearer $ADMIN_TOKEN"
# desired: HTTP 204 No Content
curl -s localhost:8000/protected/data -H "Authorization: Bearer $TOKEN"
# desired: back to the 200 `{"resource":"internal-data",...}` payload
```

### Step 8 — Rate limiting (429)

The default limit is 100 per 60 s per user. Hammer it:

```bash
for i in $(seq 1 120); do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    localhost:8000/protected/data -H "Authorization: Bearer $TOKEN")
  if [ "$CODE" = "429" ]; then echo "429 after $i requests"; break; fi
done
```

**Desired output:** `429 after 101 requests` (the boundary test is
`count <= limit` allowed, `count = limit+1` is the first 429 — that's the
documented §34 semantics).

The 429 body:

```json
{"error":"RATE_LIMIT_EXCEEDED","message":"Too many requests"}
```

✅ *Proves:* Redis-backed fixed-window limiter; boundary enforced; also
audited (visible in the admin audit trail with `reason: RATE_LIMIT_EXCEEDED`).
Also note: after a 60-second wait you can hit the endpoint again — that's
the fixed-window design (see docs/architecture.md §6 for why that's a
known/documented trade-off vs a sliding window).

### Step 9 — Backend is NOT reachable directly (bypass is impossible)

**Docker path:** just from the host:

```bash
curl -s -o /dev/null -w '%{http_code}\n' localhost:8001/internal/data
# desired: 000   (connection refused — no published port)
```

**Local-dev path** (where 8001 IS published because you ran it yourself),
test it through the *gateway* instead — the gateway refuses to expose
internal routes:

```bash
curl -s -i localhost:8000/internal/data
```

**Desired output:** HTTP **404** with a plain
`{"detail":"Not Found"}` body.

✅ *Proves:* §35.6 — `/internal/*` is backend-only territory; even the
gateway that knows about them won't admit it.

### Step 10 — Invalid/expired JWT is rejected (401)

```bash
curl -s -i localhost:8000/protected/data -H "Authorization: Bearer not-a-real-token"
```

**Desired output:** HTTP **401**,
`{"error":"AUTHENTICATION_FAILED","message":"Invalid credentials"}`.

Also try missing header entirely:

```bash
curl -s -i localhost:8000/protected/data
```

**Desired output:** same 401.

✅ *Proves:* fail-closed auth; no partial credit for almost-valid tokens.

---

## PART 4 — Run the automated test suites (the strongest proof)

### 4.1 Backend tests (self-contained; no services needed)

```bash
.venv/bin/pytest backend/tests -q
```

**Desired output:**

```text
164 passed, 221 warnings in ~25s
```

(221 warnings are all dependency deprecation notices, not failures.)

### 4.2 Backend tests against real services (PostgreSQL/Redis running)

```bash
TEST_DATABASE_URL='postgresql://postgres@127.0.0.1:5432/sentinelgate' \
TEST_REDIS_URL='redis://127.0.0.1:6379/0' \
.venv/bin/pytest backend/tests -q
```

**Desired output:** `164 passed ...` (same number — proves behavior is
consistent across SQLite and real PostgreSQL).

### 4.3 C++ engine tests

```bash
cmake -S dlp-engine -B dlp-engine/build -DCMAKE_BUILD_TYPE=Release
cmake --build dlp-engine/build --parallel
ctest --test-dir dlp-engine/build
```

**Desired output:**

```text
1/1 Test #1: aho_corasick .....................   Passed    0.00 sec
100% tests passed out of 1
```

### 4.4 The scripted §44 demo (needs a running stack on :8000)

```bash
ADMIN_PASSWORD=<from .env> bash scripts/demo.sh
```

**Desired output:**

```text
== Step 1 · register ==
  ✔ registered demoXXXX@example.com (USER role)
== Step 2 · login → JWT ==
  ✔ JWT received (… chars, bearer)
== Step 3 · normal request → GET /protected/data ==
  ✔ 200 OK — forwarded to the internal backend
== Step 4 · sensitive upload → expect 403 DLP_POLICY_BLOCK ==
  ✔ 403 — blocked by policy (AADHAAR + API_KEY detected, risk ≥ 0.8)
== Step 5 · audit record (admin reads the trail) ==
  ✔ latest BLOCK audit event …
== Step 6 · rate limiting → hammer the gateway (expect 429) ==
  ✔ 429 Too Many Requests observed
DEMO COMPLETE — all §44 steps behaved as specified.
```

Exit code 0 (`echo $?` → `0`).

### 4.5 The full Definition-of-Done smoke (Docker host — recreates everything)

```bash
bash scripts/verify_dod.sh
```

**Desired output:** runs `docker compose up --build -d`, waits healthy,
runs the whole demo, pokes the audit table with the admin, runs the pytest
suite, tears compose down, and prints:

```text
== ALL DoD SMOKE CHECKS PASSED
```

with exit code 0.

### 4.6 Regenerate the benchmark (must be script-generated, never hand-written)

```bash
.venv/bin/python scripts/benchmark_dlp.py
cat docs/benchmark.md
```

**Desired output:** a fresh markdown file with a generation timestamp, your
machine info, and a table like:

```text
| Corpus | Python (regex keyword scan) | C++ engine (incl. subprocess) |
|---|---|---|
| 10 KB  | 0.43 ms (24 MB/s)  | 1.57 ms (7 MB/s)  |
| 100 KB | 3.67 ms (28 MB/s)  | 3.50 ms (29 MB/s) |
| 1 MB   | 37.88 ms (28 MB/s) | 22.91 ms (46 MB/s) |
```

(Exact numbers vary by machine — that's the point, they're real.)

### 4.7 Optional Streamlit dashboard (§40)

```bash
.venv/bin/pip install -r dashboard/requirements.txt
export DATABASE_URL=$(grep -E '^DATABASE_URL=' .env | cut -d= -f2-)
.venv/bin/streamlit run dashboard/app.py
# open http://localhost:8501
```

**Desired output in the browser:** Total requests / ALLOW / BLOCK / REVIEW
metrics; a request-over-time bar chart; top DLP categories; top reasons;
top blocked users with risk profile; and the 50 newest audit events.
It is read-only — nothing it does can mutate your data.

---

## PART 5 — Interview Q&A cheat-sheet (the §46 questions)

**Q: Why a gateway at all?**
A: Centralized security enforcement — one place that enforces auth, RBAC,
limits, data-inspection policies, and audit so every backend doesn't
re-implement them (and never gets them wrong).

**Q: Difference between authentication and authorization?**
A: Authentication answers *who are you* (JWT) → 401 on failure;
authorization answers *what may you do* (RBAC + policies) → 403 on
failure. They're separate stages in the code (`get_current_user` vs
`require_role`).

**Q: How does rate limiting work? Why Redis?**
A: Fixed-window counters keyed `rate_limit:{user_id}:{window}` in Redis.
Window = `epoch // 60`. INCR + EXPIRE; `count <= limit` allowed. Redis
because it's shared across gateway instances — in-process memory would
give each replica its own inconsistent counter.

**Q: What happens if Redis goes down?**
A: Fail closed — the limiter raises, the request is rejected with
`503 INTERNAL_SECURITY_ERROR`, audited as `REDIS_UNAVAILABLE`. Never
silently allowed.

**Q: Why a fixed window instead of a sliding window?**
A: Deliberate simplicity for a one-week MVP; the trade-off (~2× burst
around window edges) is documented in README §17, and the fix is listed
under future work, not claimed as done.

**Q: Why Aho-Corasick? What's its complexity?**
A: Single-pass multi-pattern keyword matching — O(text length) once the
automaton is built, independent of the number of patterns. Implemented
with trie + failure links in C++, wrapped as a CLI.

**Q: How is the C++ engine integrated? What if it dies?**
A: Subprocess per region with a 2-second timeout; Python validates the
output (JSON shape, known categories, `detected` vs `matches`
consistency) before trusting it. Any failure → 500 `INTERNAL_SECURITY_ERROR`
(audited `DLP_ENGINE_FAILURE`) — fail closed.

**Q: What if PostgreSQL goes down?**
A: Auth/policy lookups fail → requests reject; audit writes are
best-effort so a bookkeeping failure never flips a decision;
`/health` shows 503 with the failing check named.

**Q: What if the C++ DLP engine fails?**
A: Same fail-closed story — 500, never allow (covered by test §35.8).

**Q: How would you scale this gateway?**
A: Gateway is stateless (JWT identity) and all shared state already sits
in Redis/PostgreSQL, so replicas behind a load balancer are the natural
next step; counters stay consistent across instances. Complex
windowing/distributed policy cache is future work (spec §47).

**Q: How would you handle a compromised JWT?**
A: Expiry is short (30 min default); today a deactivated account's token
stops working immediately (`is_active` check). A real revocation story
(denylist) is future work — honestly documented.

**Q: How would you reduce DLP false positives?**
A: Layered guards I actually built: context windows (a bare 10-digit
number is only flagged near `phone/mobile/…`), Luhn checksum for cards,
minimum value lengths for `api_key=`; plus the pattern registry is
extensible without rewriting the scanner.

**Q: How do you know secrets never leak into logs?**
A: Structured key=value logging walks every field and redacts deny-listed
keys (password/token/api_key/secret/authorization/card/aadhaar…) plus any
bearer-shaped value; audit rows store only category names; tested by
§35.5 and a dedicated log-redaction test.

---

## PART 6 — Clean-up when you're done

```bash
# if you ran Docker:
docker compose down            # stops everything (–v keeps postgres data)
docker compose down –v         # also wipes the postgres volume

# if you ran local services:
#   Ctrl-C the two uvicorn terminals, then:
scripts/dev_services.sh stop
scripts/dev_services.sh status
# desired: postgres: STOPPED / redis: STOPPED
```

---

## PART 7 — What to put on your resume (only claims the code backs)

```text
SentinelGate | Zero-Trust Security Gateway & DLP Engine
Python, FastAPI, C++17, PostgreSQL, Redis, Docker, JWT, Argon2,
Aho-Corasick, REST APIs

• Built a Zero-Trust security gateway implementing JWT authentication,
  RBAC, Redis-backed fixed-window rate limiting, DLP inspection, risk
  scoring and policy-based request enforcement (ALLOW/BLOCK/REVIEW), with
  every security decision audited in PostgreSQL and enforced fail-closed.

• Developed a C++17 Aho-Corasick multi-pattern DLP scanner with a
  documented subprocess CLI contract, integrated into a FastAPI gateway
  with output validation and a 2 s timeout; measured against a Python
  regex baseline by a reproducible benchmark script (1 MB corpus:
  ~38 ms Python vs ~23 ms C++ subprocess-inclusive).

• Implemented PostgreSQL-backed security audit logging with request-ID
  tracing, log-redaction of sensitive keys/values, and 164 automated
  integration + security tests (incl. all ten §35 security checks)
  passing against both SQLite/fakeredis and real PostgreSQL 16 + Redis 7.
```

*(Numbers in the third bullet are real and re-runnable — regenerate
`docs/benchmark.md` fresh before quoting your own.)*
