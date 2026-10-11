"""SentinelGate Zero-Trust Security Gateway.

Central reverse-proxy security gateway evaluating all inbound requests:
JWT Authentication -> RBAC Authorization -> Rate Limiting -> DLP Inspection ->
Risk Scoring -> Policy Evaluation -> Decision (Allow/Block/Review) -> Audit Logging.
"""

from __future__ import annotations

import logging
import sys

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.core.database import engine
from app.core.redis_client import create_redis_client
from app.api import auth, protected, admin, audit, policies

logger = logging.getLogger("sentinelgate")


def configure_logging() -> None:
    """Configure structured JSON logging with automatic secret redaction."""
    from app.core.logging import configure_logging as _configure

    _configure()


# Test hook: when set (e.g. test fixtures), health checks use this client.
_redis_override = None

app = FastAPI(
    title="SentinelGate",
    description=(
        "Zero-Trust security gateway: JWT authentication, RBAC, rate limiting, "
        "DLP inspection, risk scoring and policy enforcement."
    ),
    version="1.0.0",
)

# --------------------------------------------------------------------------- #
# Error Handling: Uniform error shape {"error": CODE, "message": ...}
# Internal exceptions and stack traces are never exposed to clients.
# --------------------------------------------------------------------------- #

from app.core.errors import (
    SentinelGateError,
    AuthenticationFailed,
    AuthorizationFailed,
)
from app.services.auth_service import RegistrationConflict


def install_exception_handlers(application: FastAPI) -> None:
    """Attach uniform security-compliant error handlers to the FastAPI app."""

    @application.exception_handler(SentinelGateError)
    async def gate_error_handler(request: Request, exc: SentinelGateError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.error_code, "message": exc.message},
        )

    @application.exception_handler(RegistrationConflict)
    async def registration_conflict_handler(
        _request: Request, exc: RegistrationConflict
    ) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.error_code, "message": exc.message},
        )

    @application.exception_handler(RequestValidationError)
    async def validation_handler(
        _request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Detailed validation issues go to server logs only — never to the client.
        logger.warning("request validation failed: %s", exc.errors())
        return JSONResponse(
            status_code=422,
            content={"error": "INVALID_REQUEST", "message": "Request body is invalid"},
        )

    @application.exception_handler(Exception)
    async def unhandled_handler(_request: Request, exc: Exception) -> JSONResponse:
        # Fail closed: convert unexpected runtime failures into a generic 500.
        logger.exception("unhandled error: %s", type(exc).__name__)
        return JSONResponse(
            status_code=500,
            content={
                "error": "INTERNAL_SECURITY_ERROR",
                "message": "Internal security error",
            },
        )


configure_logging()
install_exception_handlers(app)

# --------------------------------------------------------------------------- #
# Middleware: Request tracing and correlation ID propagation
# --------------------------------------------------------------------------- #

from app.middleware.request_context import RequestContextMiddleware

app.add_middleware(RequestContextMiddleware)


# --------------------------------------------------------------------------- #
# CORS Security: Disabled by default, strict explicit allowlist when enabled
# --------------------------------------------------------------------------- #

from app.core.config import get_settings

origins = get_settings().cors_origins()
if origins:
    from fastapi.middleware.cors import CORSMiddleware

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,  # Explicit list, never wildcard "*"
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    )
else:
    logger.info("CORS disabled (CORS_ALLOWED_ORIGINS is empty)")

app.include_router(auth.router)
app.include_router(protected.router)
app.include_router(admin.router)
app.include_router(audit.router)
app.include_router(policies.router)


# --------------------------------------------------------------------------- #
# Microservice Isolation: /internal/* routes are never exposed externally
# --------------------------------------------------------------------------- #

@app.api_route(
    "/internal/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"]
)
def internal_not_routed(path: str) -> JSONResponse:
    return JSONResponse(status_code=404, content={"detail": "Not Found"})


# --------------------------------------------------------------------------- #
# Health Check Endpoint
# --------------------------------------------------------------------------- #

def check_postgres() -> str:
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    return "ok"


def check_redis() -> str:
    from app.core.redis_client import _client_override

    client = _client_override if _client_override is not None else create_redis_client()
    return "ok" if client.ping() else "error"


@app.get("/health", tags=["health"])
def health() -> JSONResponse:
    checks = {"postgres": "error", "redis": "error"}
    for name, checker in (("postgres", check_postgres), ("redis", check_redis)):
        try:
            checks[name] = checker()
        except Exception as exc:  # noqa: BLE001 - health must never raise
            logger.warning("health check %s failed: %s", name, type(exc).__name__)

    if all(status == "ok" for status in checks.values()):
        return JSONResponse(status_code=200, content={"status": "ok", "checks": checks})
    return JSONResponse(
        status_code=503,
        content={
            "status": "degraded",
            "checks": checks,
            "error": "SERVICE_UNAVAILABLE",
            "message": "One or more dependencies are unhealthy",
        },
    )


def main() -> int:  # pragma: no cover
    """Fail fast at startup when required configuration is missing."""
    try:
        from app.core.config import get_settings

        get_settings()
    except Exception as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
