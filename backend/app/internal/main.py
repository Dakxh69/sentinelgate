"""Internal demo backend service.

Separate entrypoint executed as an internal microservice:
    uvicorn app.internal.main:app --host 0.0.0.0 --port 8001

The internal backend owns business logic exclusively. It does not duplicate
security checks (authentication, RBAC, rate limiting, DLP) which are enforced
by the gateway before requests are forwarded. It trusts sanitized identity headers
(X-User-Id, X-User-Role, X-Request-ID) set by the gateway.

Endpoints:
    GET  /internal/data     -> Returns payload with echoed user context
    POST /internal/upload   -> Receives upload body and reports byte count
    GET  /internal/health   -> Container health probe
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(
    title="SentinelGate Internal Backend",
    description=(
        "Internal microservice reachable exclusively through the "
        "SentinelGate gateway."
    ),
    version="1.0.0",
)

# Alias used by tests to run this ASGI app in-process
internal_app = app


@app.get("/internal/health")
def health() -> JSONResponse:
    """Liveness probe for healthcheck monitoring."""
    return JSONResponse(status_code=200, content={"status": "ok"})


@app.get("/internal/data")
def data(request: Request) -> JSONResponse:
    """Demo payload returning data and reflecting gateway identity headers."""
    return JSONResponse(
        status_code=200,
        content={
            "resource": "internal-data",
            "served_for": request.headers.get("X-User-Id"),
            "role": request.headers.get("X-User-Role"),
            "request_id": request.headers.get("X-Request-ID"),
            "items": ["alpha", "beta", "gamma"],
        },
    )


@app.post("/internal/upload")
async def upload(request: Request) -> JSONResponse:
    """Accept an upload payload and report its byte count."""
    body = await request.body()
    return JSONResponse(
        status_code=200,
        content={
            "received_bytes": len(body),
            "request_id": request.headers.get("X-Request-ID"),
            "served_for": request.headers.get("X-User-Id"),
        },
    )
