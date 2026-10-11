"""Request context middleware for correlation tracing and metadata propagation.

Assigns and validates request correlation IDs:
  - Validates client-supplied X-Request-ID (^[A-Za-z0-9._-]{8,64}$) against injection.
  - Automatically generates cryptographically unique UUID4 IDs when omitted or invalid.
  - Guarantees X-Request-ID is attached to every HTTP response.
  - Populates client IP, request path, and method into request state for audit & rate-limiting.
"""

from __future__ import annotations

import re
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{8,64}$")


def client_ip(request: Request) -> str:
    """Best-effort client IP (no X-Forwarded-For trust: local gateway)."""
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attach request ID + context to every request; echo ID in response."""

    async def dispatch(self, request: Request, call_next):
        incoming = request.headers.get("X-Request-ID", "")
        request_id = (
            incoming if _REQUEST_ID_PATTERN.match(incoming) else uuid.uuid4().hex
        )
        request.state.request_id = request_id
        request.state.method = request.method
        request.state.path = request.url.path
        request.state.source_ip = client_ip(request)

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response
