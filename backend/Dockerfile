# ---------------------------------------------------------------------------
# SentinelGate Production Container Image
#
# Multi-stage build:
#   Stage 1 (dlp-builder): Compiles the high-performance C++ Aho-Corasick engine
#   Stage 2 (runtime):     Python 3.12 slim runtime with gateway application
# ---------------------------------------------------------------------------

# ----------------------------- stage 1: C++ builder -------------------------
FROM python:3.12-slim AS dlp-builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake g++ make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
# Host build artifacts (dlp-engine/build) must not leak into the image:
# a stale CMakeCache.txt would break the in-container cmake configure.
RUN rm -rf dlp-engine
COPY dlp-engine/ ./dlp-engine/
RUN rm -rf dlp-engine/build \
    && cmake -S dlp-engine -B dlp-engine/build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build dlp-engine/build --parallel --target dlp-engine \
    && test -x dlp-engine/build/dlp-engine \
    && cp dlp-engine/build/dlp-engine /dlp-engine-binary
# Build context note: compose sets the context to the repo root so both the
# C++ engine and the backend sources are visible to one multi-stage build.

# ----------------------------- stage 2: runtime -----------------------------
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependencies first for layer caching
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Compiled C++ DLP engine at configured path: /app/dlp-engine
COPY --from=dlp-builder /dlp-engine-binary /app/dlp-engine
ENV DLP_ENGINE_PATH=/app/dlp-engine

# Application code + Alembic setup (paths relative to the repo-root context)
COPY backend/alembic.ini .
COPY backend/app/ ./app/

EXPOSE 8000

# Apply migrations, run the seed, then serve the gateway.
CMD ["sh", "-c", "alembic upgrade head && python -m app.db.seed && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
