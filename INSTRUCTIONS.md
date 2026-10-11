# SentinelGate — Developer Instructions

> **Complete reference for understanding, running, and extending SentinelGate.**
> Read this top-to-bottom once to fully understand the project.

---

## Table of Contents

1. [What is SentinelGate?](#1-what-is-sentinelgate)
2. [Architecture overview](#2-architecture-overview)
3. [Request pipeline — step by step](#3-request-pipeline--step-by-step)
4. [Repository layout](#4-repository-layout)
5. [Prerequisites](#5-prerequisites)
6. [Local development setup (without Docker)](#6-local-development-setup-without-docker)
7. [Docker Compose setup (recommended)](#7-docker-compose-setup-recommended)
8. [Environment variables reference](#8-environment-variables-reference)
9. [Running the test suite](#9-running-the-test-suite)
10. [API quick reference](#10-api-quick-reference)
11. [DLP detection rules](#11-dlp-detection-rules)
12. [Risk scoring model](#12-risk-scoring-model)
13. [Policy engine](#13-policy-engine)
14. [C++ DLP engine (optional)](#14-c-dlp-engine-optional)
15. [Dashboard](#15-dashboard)
16. [Key design decisions](#16-key-design-decisions)
17. [Extending the project](#17-extending-the-project)
18. [Troubleshooting](#18-troubleshooting)

---

## 1. What is SentinelGate?

SentinelGate is a **Zero-Trust security gateway** that sits between clients
and a protected backend microservice. Before allowing any request through, it:

- Authenticates the caller with a **JWT**
- Checks the caller's **role (RBAC)**
- Applies **rate limiting** using Redis
- Scans the request payload for **sensitive data (DLP)**
- Computes a **risk score**
- Evaluates **configurable security policies** (ALLOW / BLOCK / REVIEW)
- **Audits every decision** in PostgreSQL — success or failure

The system is **fail-closed**: if any security component fails, the request
is rejected. A broken DLP engine, a crashed Redis, or an unexpected exception
never causes the gateway to open up.

---

## 2. Architecture overview

```
┌──────────────────────────────────────────────────────────────┐
│                         Client                               │
└────────────────────────────┬─────────────────────────────────┘
                             │  HTTP
                             ▼
┌──────────────────────────────────────────────────────────────┐
│               SentinelGate Gateway  :8000                    │
│                                                              │
│  FastAPI  ──►  Security Pipeline  ──►  Audit (PostgreSQL)    │
│                    │                                         │
│            ┌───────┴──────────┐                              │
│            ▼                  ▼                              │
│         Redis             DLP Engine                         │
│     (rate limits,       (Python regex +                      │
│  security counters)   optional C++ binary)                   │
└──────────────────────────┬───────────────────────────────────┘
                           │  Forward (ALLOW only)
                           ▼
┌──────────────────────────────────────────────────────────────┐
│         Backend Microservice  :8001  (/internal/*)           │
│         (demo service — never exposed externally)            │
└──────────────────────────────────────────────────────────────┘
```

**Components:**

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Gateway | Python 3.12, FastAPI, SQLAlchemy | Main security pipeline |
| Database | PostgreSQL | User accounts, audit events, policies |
| Cache | Redis | Rate-limit counters, security event counters |
| DLP Engine | C++ (optional) | Aho-Corasick keyword scanner |
| Dashboard | HTML/JS | Read-only admin UI for audit logs |

---

## 3. Request pipeline — step by step

Every request to `/protected/*` or `/admin/*` passes through this pipeline
**in order**. Short-circuit happens immediately on rejection.

```
Client request
   │
   ▼
1. Request Validation  ── bad JSON/body? → 422 INVALID_REQUEST
2. JWT Authentication  ── no/invalid token? → 401 AUTHENTICATION_FAILED
3. RBAC Authorization  ── wrong role? → 403 AUTHORIZATION_FAILED
4. Rate Limiting       ── over 100 req/60s? → 429 RATE_LIMIT_EXCEEDED
   │                       (Redis fixed-window counter, per user)
   ▼
5. DLP Inspection      ── scan body + query string for:
   │                       EMAIL / PHONE / AADHAAR / CREDIT_CARD /
   │                       API_KEY / PASSWORD / SECRET
   ▼
6. Risk Scoring        ── multi-factor score (0.0–1.0)
   │                       base = category weight
   │                       + external upload modifier (+0.20)
   │                       + suspicious behavior modifier (+0.10)
   ▼
7. Policy Evaluation   ── evaluate all DB rules (most restrictive wins):
   │                       BLOCK → 403 DLP_POLICY_BLOCK
   │                       REVIEW → 202 REVIEW (not forwarded)
   │                       ALLOW → forward to backend
   ▼
8. Forward (ALLOW)     ── sanitized headers only (X-User-Id, X-User-Role,
   │                       X-Request-ID) — raw auth headers stripped
   ▼
9. Audit               ── always written to PostgreSQL (every decision)
```

**Fail-closed guarantees:**
- DLP engine error → 500 (never allowed through)
- Policy engine error → 500 (never allowed through)
- Redis failure during rate limiting → 503 REDIS_UNAVAILABLE
- Oversized body (>1 MiB) → flagged `unscanned: true` → policy blocks

---

## 4. Repository layout

```
SentinalGate/
├── backend/                    # Main FastAPI gateway service
│   ├── app/
│   │   ├── api/                # Route handlers
│   │   │   ├── auth.py         # POST /auth/register, /auth/login
│   │   │   ├── protected.py    # GET /protected/data|profile, POST /protected/upload
│   │   │   ├── admin.py        # GET /admin/policies (ADMIN only)
│   │   │   ├── audit.py        # GET /audit/events (ADMIN only)
│   │   │   └── policies.py     # CRUD /policies/* (ADMIN only)
│   │   ├── core/
│   │   │   ├── config.py       # Pydantic settings (reads .env)
│   │   │   ├── database.py     # SQLAlchemy engine + session factory
│   │   │   ├── dependencies.py # get_current_user, require_role FastAPI deps
│   │   │   ├── errors.py       # Typed error hierarchy (SentinelGateError)
│   │   │   ├── logging.py      # Structured JSON logging + secret redaction
│   │   │   ├── redis_client.py # Redis connection factory
│   │   │   └── security.py     # JWT encode/decode, Argon2id hashing
│   │   ├── db/
│   │   │   ├── migrations.py   # SQLAlchemy table creation (create_all)
│   │   │   └── seed.py         # Initial admin + user + default policies
│   │   ├── middleware/
│   │   │   └── request_context.py  # Request ID, IP, method/path on request.state
│   │   ├── models/             # SQLAlchemy ORM models
│   │   │   ├── user.py         # User (id, username, email, role, password_hash)
│   │   │   ├── audit_event.py  # AuditEvent (immutable audit trail)
│   │   │   └── policy.py       # Policy (configurable security rules)
│   │   ├── schemas/            # Pydantic request/response schemas
│   │   ├── services/
│   │   │   ├── auth_service.py       # Register, login business logic
│   │   │   ├── audit_service.py      # Write audit events + security counters
│   │   │   ├── dlp_service.py        # DLP pattern registry + scanner
│   │   │   ├── dlp_pipeline.py       # DLP + risk orchestration for pipeline
│   │   │   ├── gateway_service.py    # Top-level pipeline orchestration
│   │   │   ├── policy_pipeline.py    # Policy stage (wraps policy_service)
│   │   │   ├── policy_service.py     # Stateless policy rule evaluation engine
│   │   │   ├── rate_limit_service.py # Redis fixed-window rate limiter
│   │   │   └── risk_service.py       # Multi-factor risk scorer
│   │   └── main.py             # FastAPI app + error handlers + CORS + health
│   ├── tests/                  # pytest test suite (unit + integration)
│   ├── Dockerfile
│   └── requirements.txt
├── dlp-engine/                 # Optional C++ Aho-Corasick DLP engine
│   ├── src/
│   ├── CMakeLists.txt
│   └── README.md
├── dashboard/                  # Admin dashboard (static HTML/JS)
│   └── index.html
├── docs/
│   ├── architecture.md         # Detailed architecture documentation
│   ├── api.md                  # Full API reference
│   ├── benchmark.md            # Performance benchmark methodology
│   └── threat-model.md         # Threat model and security analysis
├── scripts/
│   ├── dev_services.sh         # Start/stop local PostgreSQL + Redis
│   └── build_dlp_engine.sh     # Build the C++ DLP engine binary
├── docker-compose.yml          # Full stack: gateway + backend + postgres + redis
├── pytest.ini                  # pytest configuration
├── .env.example                # Environment variable template
└── README.md                   # Project overview
```

---

## 5. Prerequisites

**For local development (without Docker):**
- Python 3.12+
- PostgreSQL 14+ (local or via `scripts/dev_services.sh`)
- Redis 7+ (local or via `scripts/dev_services.sh`)
- `libpq-dev` or equivalent (for psycopg3)

**For Docker Compose (recommended):**
- Docker 24+
- Docker Compose v2

**Optional (C++ DLP engine):**
- CMake 3.20+
- GCC 11+ or Clang 14+

---

## 6. Local development setup (without Docker)

### Step 1: Clone and create virtual environment

```bash
git clone https://github.com/<your-username>/SentinelGate.git
cd SentinelGate
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
```

### Step 2: Configure environment

```bash
cp .env.example .env
# Edit .env — set DATABASE_URL, REDIS_URL, JWT_SECRET at minimum
```

### Step 3: Start local services

```bash
bash scripts/dev_services.sh start
# Starts PostgreSQL on :5433 and Redis on :6380 using local data dirs
```

### Step 4: Initialize the database

```bash
python -m app.db.migrations    # Creates all tables
python -m app.db.seed          # Seeds admin user + default policies
```

Seed creates:
- **Admin:** `admin@sentinelgate.local` / `AdminPass!Secure2026` (role: `admin`)
- **User:** `user@sentinelgate.local` / `UserPass!Secure2026` (role: `user`)

### Step 5: Run the gateway

```bash
# From the SentinelGate/ root:
PYTHONPATH=backend uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

The API is now available at `http://localhost:8000`.
Interactive docs: `http://localhost:8000/docs`

---

## 7. Docker Compose setup (recommended)

Brings up the complete stack (gateway + backend microservice + PostgreSQL + Redis):

```bash
cp .env.example .env   # configure if needed (defaults work for Docker)

docker compose up --build
```

Services:
| Service | Internal port | Exposed |
|---------|--------------|---------|
| gateway | 8000 | `localhost:8000` |
| backend | 8001 | not exposed |
| postgres | 5432 | not exposed |
| redis | 6379 | not exposed |

Wait for the health check to go green:
```bash
curl http://localhost:8000/health
# {"status": "ok", "checks": {"postgres": "ok", "redis": "ok"}}
```

---

## 8. Environment variables reference

Copy `.env.example` to `.env` and set these values:

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | ✅ | PostgreSQL DSN (`postgresql+psycopg://user:pass@host:port/db`) |
| `REDIS_URL` | ✅ | Redis DSN (`redis://host:port/db`) |
| `JWT_SECRET` | ✅ | Random 32+ byte secret for JWT signing |
| `JWT_EXPIRATION_MINUTES` | ❌ | Token lifetime in minutes (default: 30) |
| `RATE_LIMIT_REQUESTS` | ❌ | Max requests per window (default: 100) |
| `RATE_LIMIT_WINDOW_SECONDS` | ❌ | Window duration in seconds (default: 60) |
| `BACKEND_URL` | ❌ | Internal backend URL (default: `http://backend:8001`) |
| `DLP_ENGINE_PATH` | ❌ | Path to C++ binary (unset = Python-only mode) |
| `CORS_ALLOWED_ORIGINS` | ❌ | Comma-separated allowed origins (empty = CORS off) |
| `POSTGRES_PASSWORD` | ❌ | Used by Docker Compose to init the DB container |
| `ADMIN_PASSWORD` | ❌ | Password for seeded admin account |
| `SEED_USER_PASSWORD` | ❌ | Password for seeded user account |

> **Never commit `.env` to version control.** The `.gitignore` excludes it.

Generate a secure `JWT_SECRET`:
```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

---

## 9. Running the test suite

```bash
# Activate venv first, then from the SentinalGate/ root:
pytest
```

The test suite requires PostgreSQL + Redis to be running. Tests use an
isolated test database (configured in `backend/tests/conftest.py`).

Run with verbosity:
```bash
pytest -v
```

Run only a specific module:
```bash
pytest backend/tests/test_dlp_service.py -v
```

---

## 10. API quick reference

### Authentication

```bash
# Register a new user
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "email": "alice@example.com", "password": "StrongPass!99"}'

# Login and get a JWT token
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "StrongPass!99"}'
# Response: {"access_token": "eyJ...", "token_type": "bearer"}
```

### Protected endpoints

```bash
TOKEN="eyJ..."  # from login response

# GET /protected/data — requires USER or ADMIN role
curl http://localhost:8000/protected/data \
  -H "Authorization: Bearer $TOKEN"

# POST /protected/upload — DLP scans the body
curl -X POST http://localhost:8000/protected/upload \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"data": "my credit card is 4111111111111111"}'
# → 403 DLP_POLICY_BLOCK (Luhn-valid card number detected)

# GET /protected/profile — gateway-owned, always returns DLP + risk result
curl http://localhost:8000/protected/profile \
  -H "Authorization: Bearer $TOKEN"
```

### Admin endpoints (ADMIN role required)

```bash
ADMIN_TOKEN="..."  # login as admin@sentinelgate.local

# List all policies
curl http://localhost:8000/admin/policies \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# View audit events
curl "http://localhost:8000/audit/events?limit=10" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

### Health check (no auth)

```bash
curl http://localhost:8000/health
```

---

## 11. DLP detection rules

The Python DLP scanner (`backend/app/services/dlp_service.py`) detects
seven categories using regex patterns + validators:

| Category | Detection method | Confidence | Notes |
|----------|-----------------|------------|-------|
| `EMAIL` | Regex | 0.90 | Standard RFC-pragmatic pattern |
| `PHONE` | Regex (two rules) | 0.85 / 0.70 | +91 prefix: 0.85. Bare 10-digit: 0.70 only with nearby context keyword (phone/mobile/contact), else suppressed |
| `AADHAAR` | Regex + context | 0.95 / 0.60 | 12-digit: 0.95 with aadhaar/uid/uidai keyword, 0.60 without |
| `CREDIT_CARD` | Validator (Luhn) | 0.90 | 13–19-digit sequences that pass Luhn check |
| `API_KEY` | Regex | 0.95 | `api_key=`, `token=`, `x-api-key:` with value ≥ 8 chars |
| `PASSWORD` | Regex | 0.95 | `password=`, `passwd=`, `pwd=` and JSON `"password":` form |
| `SECRET` | Regex | 0.98 | `secret=`, `client_secret=`, PEM private key blocks |

**Scan targets:** request body + URL query string. Authorization header is never scanned (it contains standard bearer tokens).

**Oversized payloads:** Bodies > 1 MiB are flagged `unscanned: true`. The policy engine treats `unscanned: true` as sensitive, so it will be blocked by the default policy.

---

## 12. Risk scoring model

Risk is calculated in `backend/app/services/risk_service.py`:

```
final_score = min(1.0, base_weight + context_modifiers)
```

**Base weights (by detected category — highest wins):**

| Category | Weight |
|----------|--------|
| EMAIL | 0.10 |
| PHONE | 0.20 |
| AADHAAR | 0.70 |
| CREDIT_CARD | 0.80 |
| PASSWORD | 0.80 |
| API_KEY | 0.90 |
| SECRET | 0.90 |

**Context modifiers:**

| Modifier | Value | Trigger |
|----------|-------|---------|
| `external_upload` | +0.20 | POST `/protected/upload` |
| `suspicious_behavior` | +0.10 | IP has ≥ 5 security events (401/403/429) in 600s |

**Example:** CREDIT_CARD (0.80) + external_upload (+0.20) = **1.0 (capped)**

---

## 13. Policy engine

Policies are stored in PostgreSQL and evaluated by `backend/app/services/policy_service.py`.

### Policy fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Human-readable policy name |
| `role` | string\|null | Match a specific role (`admin`/`user`/`guest`) or any |
| `path_pattern` | string\|null | Glob or exact path (`/protected/*`, `/*`, `/protected/upload`) |
| `http_method` | string\|null | Match `GET`, `POST`, etc., or any |
| `sensitive_required` | bool\|null | Match only requests with/without detections |
| `minimum_risk` | float\|null | Match only when risk score ≥ this value |
| `action` | string | `ALLOW`, `BLOCK`, or `REVIEW` |
| `enabled` | bool | Whether rule is active |

### Evaluation logic

1. All enabled rules that match the request are collected
2. **Most restrictive action wins:** BLOCK > REVIEW > ALLOW
3. Ties within the same action are broken by: more constraints > longer pattern > lower ID
4. **No matching rules + sensitive data = BLOCK** (fail closed)
5. **No matching rules + clean request = ALLOW**
6. Corrupt rule actions default to BLOCK

### Manage policies via API

```bash
# Create a policy (ADMIN token required)
curl -X POST http://localhost:8000/policies \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Block high-risk uploads",
    "path_pattern": "/protected/upload",
    "sensitive_required": true,
    "minimum_risk": 0.7,
    "action": "BLOCK"
  }'
```

---

## 14. C++ DLP engine (optional)

An optional Aho-Corasick keyword scanner written in C++ provides an
additional signal layer on top of the Python regex scanner.

### Build

```bash
bash scripts/build_dlp_engine.sh
# Produces: dlp-engine/build/dlp-engine binary
```

Or manually:
```bash
cd dlp-engine
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

### Enable

Set in `.env`:
```bash
DLP_ENGINE_PATH=/path/to/dlp-engine/build/dlp-engine
```

Or in Docker Compose, uncomment the `DLP_ENGINE_PATH` line.

### Behavior

- When configured, the C++ binary runs on each scan region alongside the Python scanner
- Results are **merged** (Python value-detectors + C++ keyword signals)
- Any C++ failure (crash, timeout, non-zero exit, bad output) → `DLPEngineError` → request rejected with 500 (fail closed)
- Timeout: 2 seconds per scan region

### C++ engine interface

```
# Stdin: raw text to scan
# Stdout: one JSON line
{"detected": true, "matches": ["API_KEY", "EMAIL"]}
# Exit code: 0 on success, non-zero on failure
```

---

## 15. Dashboard

A lightweight admin dashboard is included at `dashboard/index.html`.

Open it in a browser (no build step needed):
```bash
# If the gateway is running at localhost:8000:
xdg-open dashboard/index.html
```

Features:
- Login with admin credentials
- View paginated audit events (decision, risk score, categories, IP, path)
- Filter by decision type (ALLOW / BLOCK / REVIEW)

> The dashboard queries the gateway API directly via fetch(). CORS must be
> enabled if you open the HTML from a different origin than the API.
> Set `CORS_ALLOWED_ORIGINS=http://localhost` in your `.env`.

---

## 16. Key design decisions

### Why fail-closed everywhere?

Zero-Trust means: **deny by default**. If the gateway cannot verify that a
request is safe, it must reject it. This applies to:
- DLP engine failures → 500, not a pass-through
- Redis failures during rate limiting → 503
- Oversized bodies → treated as sensitive
- Unknown policy actions in DB → treated as BLOCK

### Why is audit always written?

Security decisions are only meaningful if they are recorded. The audit step
runs regardless of whether the decision was ALLOW, BLOCK, or REVIEW. Even
backend failures are audited with `BACKEND_UNAVAILABLE`.

### Why separate gateway and backend processes?

The backend microservice (`/internal/*`) is never reachable externally — it
only accepts connections from the gateway. This enforces that all external
traffic passes through the full security pipeline.

### Why Redis for rate limiting?

Fixed-window counters in Redis are shared across all gateway instances. A
purely in-memory counter would let each instance allow the full rate limit
independently, breaking the intent of the policy.

### Sensitive data is never logged

The logging system (`backend/app/core/logging.py`) applies automatic
redaction. Category labels (e.g. `"CREDIT_CARD"`) are logged, but raw
matched values never are. Audit events store category names, not values.

---

## 17. Extending the project

### Add a new DLP detection category

1. Add a `PatternDef` entry to the `PATTERNS` list in `backend/app/services/dlp_service.py`
2. Add a weight to `CATEGORY_WEIGHTS` in `backend/app/services/risk_service.py`
3. Add the category name to `KNOWN_CATEGORIES` in `dlp_service.py` (so the C++ engine can report it)
4. Write a unit test in `backend/tests/test_dlp_service.py`

### Add a new protected route

1. Add the route handler in `backend/app/api/protected.py`
2. Add the route to `FORWARDED_ROUTES` in `backend/app/services/gateway_service.py` if it should forward to the backend
3. Add a corresponding route in the backend microservice (`dev-env/`)

### Add a new policy

Use the REST API (`POST /policies`) or add a row to the seed script
(`backend/app/db/seed.py`) for it to be created on every fresh database init.

---

## 18. Troubleshooting

### `connection refused` on startup

Services (Postgres, Redis) are not running.
- Local: `bash scripts/dev_services.sh start`
- Docker: `docker compose up`

### `401 AUTHENTICATION_FAILED` immediately

JWT_SECRET in `.env` may have changed since the token was issued, or the
token has expired (`JWT_EXPIRATION_MINUTES` default: 30).

### `503 REDIS_UNAVAILABLE` on protected routes

Redis is not reachable. The gateway fails closed on rate limit Redis
failures. Check `REDIS_URL` in `.env`.

### DLP engine binary not found

`DLP_ENGINE_PATH` is set but the binary does not exist at that path.
Build it with `bash scripts/build_dlp_engine.sh` or unset the variable
to fall back to Python-only mode.

### Tests fail with `could not connect to server`

Tests need a live PostgreSQL. Run `bash scripts/dev_services.sh start`
first, or use Docker Compose.

### `422 INVALID_REQUEST` on login/register

The request body is malformed. Ensure `Content-Type: application/json`
and that all required fields are present.

---

*SentinelGate — Zero-Trust Security Gateway & DLP Engine*
