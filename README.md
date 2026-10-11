# SentinelGate — Zero-Trust Security Gateway & DLP Engine

SentinelGate is a [project](https://github.com/) built to demonstrate a
production-style security gateway: it sits between clients and a protected
backend and evaluates **every** request before allowing it through.

## Table of contents

1. [What SentinelGate is](#1-what-sentinelgate-is)
2. [Problem being solved](#2-problem-being-solved)
3. [Architecture](#3-architecture)
4. [Request lifecycle](#4-request-lifecycle)
5. [Technology stack](#5-technology-stack)
6. [Project structure](#6-project-structure)
7. [Setup instructions](#7-setup-instructions)
8. [Environment variables](#8-environment-variables)
9. [Docker setup](#9-docker-setup)
10. [API examples](#10-api-examples)
11. [DLP rules](#11-dlp-rules)
12. [Policy examples](#12-policy-examples)
13. [C++ DLP engine](#13-c-dlp-engine)
14. [Testing](#14-testing)
15. [Benchmark methodology](#15-benchmark-methodology)
16. [Security considerations](#16-security-considerations)
17. [Limitations](#17-limitations)
18. [Future improvements](#18-future-improvements)

---

## 1. What SentinelGate is

A **Zero-Trust security gateway** with an integrated DLP (Data Loss
Prevention) engine. It receives client requests and performs, in an explicit
fixed order:

1. Request validation
2. JWT authentication
3. Role-based authorization (RBAC)
4. Rate limiting (Redis, fixed window)
5. Sensitive-data inspection / DLP (Python scanner + C++ Aho-Corasick engine)
6. Risk scoring
7. Policy evaluation
8. ALLOW / BLOCK / REVIEW decision
9. Audit logging (PostgreSQL)
10. Forwarding to the protected backend when allowed

It is a real, runnable system — no mock functions, no placeholder endpoints.

## 2. Problem being solved

Modern companies enforce security centrally: they do not trust requests by
default, and they do not let each backend service reinvent auth, rate limits
and data-exfiltration checks. SentinelGate demonstrates exactly that idea:

- **Never trust requests by default** — every request is authenticated,
  authorized, rate-limited, inspected, scored and policy-checked.
- **Centralized security enforcement** — the gateway owns all security
  logic; the demo backend owns business logic only (§28).
- **Sensitive data cannot leave** — request bodies (and query strings) are
  scanned for Aadhaar numbers, credit cards, API keys, passwords, secrets,
  emails and phone numbers before the request is forwarded.
- **Everything is auditable** — every security-relevant request produces an
  audit event with the decision, risk score, detected categories and reason.

## 3. Architecture

``` text
                         CLIENT
                           |  HTTP
                           v
                +-----------------------+
                |     SentinelGate      |
                |  Request Validation   |
                |  JWT Authentication   |
                |  RBAC Authorization   |
                |      Rate Limiter     |
                |       DLP Engine      |
                |      Risk Scoring     |
                |     Policy Engine     |
                |    ALLOW/BLOCK/REVIEW |
                +-----------+-----------+
                            |
              ALLOW         |            BLOCK/REVIEW
                |           +--------------------------+
                v                                      v
       Protected Backend                        Audit Database
     (internal Docker network)                 (PostgreSQL)
                |
                v
          Backend Response
```

Supporting components:

| Component   | Role                                                    |
|-------------|---------------------------------------------------------|
| Redis       | rate limiting / fixed-window counters / security events |
| PostgreSQL  | users, policies, audit events                           |
| C++ engine  | high-performance multi-pattern DLP keyword scanning     |
| Docker      | reproducible local deployment, network isolation        |
| pytest      | automated tests (including security tests)              |

Details: [`docs/architecture.md`](docs/architecture.md).

## 4. Request lifecycle

Every protected request (`GET /protected/data`, `POST /protected/upload`)
passes through the pipeline in exactly this order — the order is explicit in
code (`backend/app/services/gateway_service.py`) and asserted by a
stage-order test:

``` text
Incoming Request
      |
Request Validation
      |
Authentication            (JWT → 401 on failure)
      |
Authorization             (RBAC → 403 on failure)
      |
Rate Limiting             (Redis fixed window → 429)
      |
DLP Inspection            (body + query string; C++ engine when configured)
      |
Risk Scoring              (category weights + context modifiers, capped at 1.0)
      |
Policy Evaluation         (policies table → ALLOW/BLOCK/REVIEW)
      |
      +-- BLOCK  --> 403 DLP_POLICY_BLOCK  (audited, never forwarded)
      +-- REVIEW --> 202 held for review   (audited, never forwarded)
      |
Forward to Backend        (only ALLOW; sanitized headers only)
      |
Audit                     (always written, even for BLOCK/REVIEW)
      |
Return Response
```

Fail closed (§2.4): if any security stage fails unexpectedly (Redis down,
policy-engine error, DLP engine failure), the request is **rejected**, never
silently allowed.

## 5. Technology stack

- **Backend:** Python 3.12+, FastAPI, Uvicorn, Pydantic, SQLAlchemy 2, Alembic
- **Security:** PyJWT (HS256), Argon2id hashing (argon2-cffi)
- **Database:** PostgreSQL 16 (JSONB audit categories, BIGSERIAL PKs)
- **Cache/limits:** Redis 7 (fixed-window rate limiter, security-event counters)
- **DLP engine:** C++17 + CMake (Aho-Corasick), subprocess JSON/CLI integration
- **Containerization:** Docker + Docker Compose (multi-stage image build)
- **Testing:** pytest, FastAPI TestClient/httpx, fakeredis + SQLite fallbacks

## 6. Project structure

``` text
sentinelgate/
├── backend/
│   ├── app/
│   │   ├── main.py                  # gateway app (CORS, errors, health)
│   │   ├── internal/main.py         # demo backend (business logic only, :8001)
│   │   ├── api/                     # auth, protected, admin, policies, audit
│   │   ├── core/                    # config, security (JWT/argon2), logging
│   │   ├── middleware/              # request IDs + context
│   │   ├── models/                  # User, Policy, AuditEvent (SQLAlchemy)
│   │   ├── schemas/                 # Pydantic request/response models
│   │   ├── services/                # gateway pipeline, auth, DLP, risk,
│   │   │                            # policy, rate-limit, audit services
│   │   └── db/                      # database, migrations, seed
│   ├── tests/                       # 164 tests (unit + integration + security)
│   ├── alembic/                     # migrations
│   ├── requirements.txt
│   └── Dockerfile                   # multi-stage: C++ build + runtime
├── dlp-engine/
│   ├── include/                     # Aho-Corasick headers
│   ├── src/                         # engine, trie, CLI
│   ├── tests/                       # C++ unit tests (ctest)
│   └── CMakeLists.txt
├── docs/
│   ├── architecture.md              # components, pipeline, scaling
│   ├── api.md                       # endpoints, error catalog, CLI protocol
│   ├── threat-model.md              # 6 threats + mitigations + residual risks
│   └── benchmark.md                 # generated by scripts/benchmark_dlp.py
├── scripts/
│   ├── benchmark_dlp.py             # generates docs/benchmark.md
│   ├── demo.sh                      # scripted §44 demo
│   ├── verify_dod.sh                # automated DoD smoke (Docker host)
│   ├── e2e_docker.sh                # compose e2e smoke (Day 6)
│   └── dev_services.sh              # local PG/Redis (no-Docker dev)
├── docker-compose.yml               # gateway, backend, postgres, redis
├── spec.md                          # source-of-truth specification
├── specs/                           # 7 day-specs + implementation status
└── .env.example
```

## 7. Setup instructions

### Path A — virtualenv + local services (fastest for development)

``` bash
python -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements.txt

# local PostgreSQL + Redis without Docker (see specs/README.md environment notes)
scripts/dev_services.sh start

cp .env.example .env          # then edit: JWT_SECRET + seed passwords
export $(grep -v '^#' .env | xargs)

cd backend
alembic upgrade head
ADMIN_PASSWORD=admin-pass-123 SEED_USER_PASSWORD=user-pass-123 \
  python -m app.db.seed
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Health check: `curl localhost:8000/health` → `{"status": "ok", ...}`.
The C++ engine is optional in dev: without `DLP_ENGINE_PATH` the gateway runs
the Python scanner (documented fallback); build the engine and set the path
to enable the §26 subprocess integration.

### Path B — Docker (spec §29 setup)

``` bash
cp .env.example .env    # set JWT_SECRET, POSTGRES_PASSWORD, ADMIN_PASSWORD…
docker compose up --build -d
bash scripts/verify_dod.sh    # or: bash scripts/demo.sh
```

## 8. Environment variables

| Variable                  | Required | Default (example)                          | Purpose |
|---------------------------|----------|--------------------------------------------|---------|
| `DATABASE_URL`            | yes      | `postgresql://...@postgres:5432/sentinelgate` | SQLAlchemy connection (`postgresql://` is rewritten to `postgresql+psycopg://`; asyncpg rejected) |
| `REDIS_URL`               | yes      | `redis://redis:6379/0`                     | Rate limiting / security counters |
| `JWT_SECRET`              | **yes — no default** | —                              | JWT signing key; the app **fails fast at startup** when missing |
| `JWT_EXPIRATION_MINUTES`  | no       | `30`                                       | Token lifetime |
| `RATE_LIMIT_REQUESTS`     | no       | `100`                                      | Requests per window |
| `RATE_LIMIT_WINDOW_SECONDS` | no     | `60`                                       | Window length (fixed window) |
| `BACKEND_URL`             | no       | `http://backend:8001`                      | Internal backend target |
| `DLP_ENGINE_PATH`         | no       | unset (Python-only scanner)                | C++ engine binary; set to `/app/dlp-engine` in Docker |
| `CORS_ALLOWED_ORIGINS`    | no       | empty (CORS disabled)                      | Comma-separated origins; **never `*`** |
| `POSTGRES_PASSWORD`       | compose  | —                                          | Postgres container superuser password |
| `ADMIN_PASSWORD`          | seed     | —                                          | Seeded admin password (never hardcoded) |
| `SEED_USER_PASSWORD`      | seed     | —                                          | Seeded user password |

Commit only `.env.example`; `.env` is git-ignored.

## 9. Docker setup

``` bash
docker compose up --build -d
docker compose ps             # gateway, backend, postgres, redis
docker compose logs -f gateway
docker compose down           # teardown (pgdata volume persists)
```

- The **gateway** is the only service with a published port (`8000:8000`).
- The **backend** (same image, different entrypoint: `uvicorn
  app.internal.main:app --port 8001`) has **no published ports** — it is
  reachable only on the compose network, only through the gateway (§29/§35.6).
- Gateway starts with `alembic upgrade head && python -m app.db.seed &&
  uvicorn app.main:app`, so migrations and seed run automatically.
- Health-check-gated `depends_on`: gateway waits for postgres + redis +
  backend to be healthy.

## 10. API examples

All protected calls need `Authorization: Bearer <token>`. Full catalog:
[`docs/api.md`](docs/api.md). Interactive docs: `http://localhost:8000/docs`
(FastAPI OpenAPI).

``` bash
# register (201; duplicate → 409)
curl -s -X POST localhost:8000/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"daksh","email":"daksh@example.com","password":"strong-password"}'

# login (200 → JWT; wrong creds → 401 AUTHENTICATION_FAILED)
TOKEN=$(curl -s -X POST localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"daksh@example.com","password":"strong-password"}' | jq -r .access_token)

# normal request → 200, forwarded to the internal backend
curl -s localhost:8000/protected/data -H "Authorization: Bearer $TOKEN"

# sensitive upload → 403 DLP_POLICY_BLOCK (Aadhaar + 12-digit + api_key detected)
curl -s -X POST localhost:8000/protected/upload \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"content":"aadhaar 123456789012, api_key=supersecrettoken123"}'
# {"error":"DLP_POLICY_BLOCK","message":"Request blocked by DLP policy"}

# admin: audit trail (ADMIN only; 403 for others)
curl -s "localhost:8000/admin/audit?limit=5" -H "Authorization: Bearer $ADMIN_TOKEN"
```

## 11. DLP rules

Seven categories (§13) — a demonstration DLP engine, not production-grade PII
classification. The scanner is a **pattern registry** (`PatternDef`): adding a
rule = appending an entry, no scanner rewrite.

| Category | Trigger | Confidence | False-positive guard |
|---|---|---|---|
| `EMAIL` | pragmatic email regex `x@y.tld` | 0.90 | — |
| `PHONE` | `+91-9876543210` form | 0.85 | explicit +91 form only |
| `PHONE` | bare `9876543210` | 0.70 | **only** within ±40 chars of context words (`phone/mobile/contact/call/whatsapp`); contextless 10-digit numbers are suppressed (0.0) |
| `AADHAAR` | 12 digits | 0.95 | heuristic by design (§14.3) |
| `AADHAAR` | 12 digits contextless | 0.60 | labelled heuristic fallback |
| `CREDIT_CARD` | 13–19 digits | 0.90 | **Luhn checksum required** — failures are not reported |
| `API_KEY` | `api_key=…`, `apikey:`, `token=…`, JSON form | 0.95 | value ≥ 8 chars |
| `PASSWORD` | `password=`, `passwd=`, `pwd=`, JSON form | 0.95 | — |
| `SECRET` | `secret=`, `client_secret=`, `private_key=`, PEM blocks | 0.98 | — |

Result contract (§15) — category names + confidences only, **never raw values**:

``` json
{"detected": true, "matches": [{"type": "AADHAAR", "confidence": 0.6}]}
```

Body > 1 MiB is not scanned at all: it is truncated-and-flagged
(`unscanned: true`) and treated as sensitive by the policy layer (fail closed).
The `Authorization` header is never scanned (it is a bearer token by
construction).

## 12. Policy examples

Policies live in the `policies` table; the engine (§17–18) matches on
`role / http_method / path_pattern / sensitive_required / minimum_risk`,
most-restrictive-wins (`BLOCK > REVIEW > ALLOW`), ties broken by rule
specificity then id. No matching rule + sensitive data → **BLOCK**.

Seeded defaults:

| name | role | path_pattern | sensitive_required | minimum_risk | action |
|---|---|---|---|---|---|
| `baseline-allow` | — | `/*` | false | 0.0 | ALLOW |
| `block-user-upload-sensitive` | USER | `/protected/upload` | true | 0.50 | BLOCK |
| `review-admin-upload-sensitive` | ADMIN | `/protected/upload` | true | 0.50 | REVIEW |

Spec §17 example (create via API as admin):

``` json
{
  "name": "block-user-upload-sensitive",
  "role": "USER",
  "path_pattern": "/protected/upload",
  "sensitive_required": true,
  "minimum_risk": 0.80,
  "action": "BLOCK"
}
```

Meaning: USER + upload + sensitive data + risk ≥ 0.80 → BLOCK.
Typical risk: Aadhaar (0.70) detected on upload (+0.20) with no other
categories → 0.90; API_KEY (0.90) + upload → capped at 1.0.

## 13. C++ DLP engine

- **Algorithm:** Aho-Corasick (trie + failure links, single-pass scanning over
  the input) — see `dlp-engine/src/aho_corasick.cpp`; the default keyword set
  is the five §23 keywords (`password`, `api_key`, `secret`, `aadhaar`,
  `credit_card`).
- **Build (host):**

  ``` bash
  cmake -S dlp-engine -B dlp-engine/build -DCMAKE_BUILD_TYPE=Release
  cmake --build dlp-engine/build --parallel
  ctest --test-dir dlp-engine/build        # C++ unit tests
  ```

- **CLI contract (§26), deterministic and documented:**

  ``` bash
  echo 'api_key=secret123' | ./dlp-engine --scan
  # {"detected": true, "matches": ["API_KEY"]}
  ```

  One JSON line on stdout — `{"detected": bool, "matches": [category, ...]}`
  (sorted, deduplicated) — exit 0. Any bad invocation is a non-zero exit:
  1 bad args, 2 stdin/stdout failure, 3 engine exception.
- **Integration:** subprocess per region with a hard 2 s timeout
  (`DLP_ENGINE_PATH`). Python **validates** the C++ output (types, known
  categories, contradiction between `detected` and `matches`) before trusting
  it; keyword-only signals get the engine identity confidence 0.5, Python
  value detectors always outrank them on merge.
- **Fail closed (§26/§35.8):** missing binary, non-zero exit, timeout,
  malformed or contradictory output → the request is rejected with 500
  `INTERNAL_SECURITY_ERROR` (audited `DLP_ENGINE_FAILURE`), never allowed.

## 14. Testing

``` bash
# self-contained (SQLite + fakeredis — no services needed)
.venv/bin/pytest backend/tests -v

# against real services
TEST_DATABASE_URL='postgresql://postgres@127.0.0.1:5432/sentinelgate' \
TEST_REDIS_URL='redis://127.0.0.1:6379/0' \
.venv/bin/pytest backend/tests -v

# C++ engine tests
ctest --test-dir dlp-engine/build
```

Coverage (164 tests):

- **auth/JWT:** registration, duplicates, wrong password, expired/invalid JWT
- **authorization:** USER/GUEST/ADMIN matrix, 401 vs 403 semantics
- **rate limiting:** boundary (`count <= limit` allowed, `+1` → 429), IP
  limiter on `/auth/*`, Redis-down → fail-closed 503
- **DLP:** all seven categories + false-positive guards (Luhn, context
  windows), unscanned flagging, C++ engine validation + failure paths
- **policy:** match semantics, conflict resolution, fail-closed
  (`NO_MATCHING_POLICY`, corrupt action → BLOCK, engine error → 500)
- **integration (Day 6):** exact §6 stage order, ALLOW reaches the backend,
  BLOCK/REVIEW never forwarded, audit rows, request-ID propagation
- **security (§35):** ten explicit checks — no plaintext passwords, no JWT
  bypass, RBAC enforced, limits not bypassable, no sensitive values in
  audit/logs, `/internal/*` not exposed, invalid policy config never
  defaults to ALLOW, DLP failure never allows, ORM/parameterized SQL only,
  no wildcard CORS + generic-500 and log-redaction tests

## 15. Benchmark methodology

**Regenerated by script — the numbers below were never hand-written.**
Run `.venv/bin/python scripts/benchmark_dlp.py` to regenerate
[`docs/benchmark.md`](docs/benchmark.md).

Methodology: synthetic corpora of 10 KB / 100 KB / 1 MB with the five §23
keywords injected (~2 % density, seeded RNG — identical input for both
scanners). Warmup 3 runs, then the **median of 15 timed runs** per
implementation per size. The C++ number includes the full subprocess cost
(spawn + stdin/stdout round-trip) because that is the real integration cost
per §26; the Python number is an in-process regex keyword scan over the same
text — the same scanning task, honestly labeled.

Real measured results (this host, see docs/benchmark.md for machine details):

| Corpus | Python (regex keyword scan) | C++ engine (incl. subprocess) |
|---|---|---|
| 10 KB  | 0.43 ms (24 MB/s) | 1.57 ms (7 MB/s) |
| 100 KB | 3.67 ms (28 MB/s) | 3.50 ms (29 MB/s) |
| 1 MB   | 37.88 ms (28 MB/s) | 22.91 ms (46 MB/s) |

Interpretation: the CLI-inclusive C++ cost is dominated by process spawn at
small sizes and amortizes as corpora grow; the C++ algorithm itself scans far
faster than Python regex.

## 16. Security considerations

- **Fail closed everywhere (§2.4):** broken JWT handling, `JWT_SECRET`
  missing at startup, Redis outage, policy-engine error, DLP engine failure,
  unreadable inputs → rejection, never a silent allow. An invalid or corrupt
  stored policy action is treated as BLOCK.
- **Least privilege:** the backend receives only `X-Request-ID`,
  `X-User-Id`, `X-User-Role` — never the `Authorization` header or arbitrary
  client headers (§28). The backend publishes no ports.
- **Secret hygiene (§2.5/§20/§37):** argon2id password hashes only;
  structured `key=value` logs with a redaction denylist (password, token,
  api_key, secret, authorization, card, aadhaar…) and bearer-token-shaped
  value redaction; audit rows store category names, never raw matched values.
- **Enumerations protection:** login failures are uniformly 401 without
  distinguishing unknown email / wrong password / deactivated account.
- **No wildcard CORS:** unset `CORS_ALLOWED_ORIGINS` installs no CORS
  middleware at all; setting it enables an explicit origin list only.
- **Parameterized persistence:** all queries go through SQLAlchemy ORM;
  no string-concatenated SQL (tested).
- **Request IDs (§33):** incoming `X-Request-ID` honored only if it matches
  `^[A-Za-z0-9._-]{8,64}$` (header-injection guard), otherwise a fresh uuid4.

## 17. Limitations

Honest limitations of this one-week implementation:

- **Fixed-window rate limiting** — bursty clients can in principle reach
  ~2× the nominal limit across a window boundary; sliding windows or token
  buckets would be fairer.
- **Regex/heuristic DLP** — pattern-based scanning cannot guarantee complete
  PII detection; context windows and Luhn reduce but do not eliminate false
  positives/negatives. Not production-grade PII classification (§13).
- **Subprocess DLP engine** — one process spawn per region per request is
  correct and debuggable but would need a persistent worker/shared library
  binding at production throughput (the benchmark shows the spawn cost).
- **Single node** — the design anticipates multi-instance gateways (limits
  and counters live in Redis, not process memory), but no load balancing,
  no TLS termination, no JWT revocation list are implemented.
- **Fixed-window audit listing** and best-effort audit writes (a failed audit
  write never changes a decision) are documented simplifications, not
  transactional guarantees.
- Suspicious-behavior signal is a simple in-Redis counter keyed by
  client IP; no behavioral analytics.

## 18. Future improvements

Presented as future work (spec §47) — none of these are implemented:

- Kafka-based event streaming for audit/telemetry
- Distributed rate limiting (consistent across many gateways)
- Sliding-window rate limiter
- ML-based DLP classification, document fingerprinting, exact data matching
- File-type-aware scanning (binary formats, archives)
- TLS inspection / service-to-service mTLS
- OAuth/OIDC login federation
- Kubernetes deployment
- Prometheus/Grafana metrics, SIEM integration
- Distributed policy cache, horizontal scaling story

## Optional: Streamlit dashboard (spec §40)

A read-only Streamlit view over `audit_events` lives in `dashboard/app.py`.
It shows the §40 cards: total requests and the ALLOW/BLOCK/REVIEW split,
requests per minute over the last hour, top detected DLP categories, top
block reasons, top blocked users with their risk profile, and the 50 most
recent audit events. It **writes nothing** — only SELECTs against
`audit_events` — and touches no gateway code.

``` bash
.venv/bin/pip install -r dashboard/requirements.txt   # streamlit + pandas only
export DATABASE_URL=$(grep -E '^DATABASE_URL=' .env | cut -d= -f2-)
.venv/bin/streamlit run dashboard/app.py
# open http://localhost:8501
```

The dashboard needs the backend migrations applied and some audit traffic
(e.g. run `scripts/demo.sh` against a running gateway first).
