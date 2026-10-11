"""SentinelGate error types shared across routes and services."""

from __future__ import annotations


class SentinelGateError(Exception):
    """Base class for gateway errors carrying a safe client-facing payload."""

    status_code = 500
    error_code = "INTERNAL_SECURITY_ERROR"
    message = "Internal security error"

    # Optional callback invoked by the global handler for audit side effects.
    on_raise = None

    def __init__(self, message: str | None = None) -> None:
        super().__init__(message or self.message)
        # If a message was supplied, set it on the instance for rendering.
        if message:
            object.__setattr__(self, 'message', message)


class AuthenticationFailed(SentinelGateError):
    status_code = 401
    error_code = "AUTHENTICATION_FAILED"
    message = "Invalid credentials"


class AuthorizationFailed(SentinelGateError):
    status_code = 403
    error_code = "AUTHORIZATION_FAILED"
    message = "Insufficient permissions"
