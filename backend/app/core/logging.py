"""Structured logging with automated sensitive data redaction.

All log lines format as structured key=value pairs:
    INFO request_id=abc method=POST path=/protected/upload user_id=42

`log_event()` sanitizes nested structures and automatically redacts credentials,
tokens, card numbers, passwords, and private identities. Raw bodies and Authorization
headers are never committed to disk or telemetry streams.
"""

from __future__ import annotations

import logging
import re
import sys
from typing import Any

# Keys whose values must never appear in logs (case-insensitive match).
REDACT_KEYS = frozenset(
    {
        "password",
        "token",
        "access_token",
        "api_key",
        "apikey",
        "secret",
        "authorization",
        "card",
        "aadhaar",
        "uid",
        "private_key",
    }
)

_REDACTED = "[REDACTED]"

# Values that look like bearer tokens / JWTs get redacted even under safe keys.
_BEARER_LIKE = re.compile(r"^Bearer\s+|^eyJ[A-Za-z0-9_-]{10,}")


def _sanitize(value: Any) -> Any:
    """Redact sensitive-looking values; walk dicts/lists recursively."""
    if isinstance(value, dict):
        return {
            str(k): (_REDACTED if str(k).lower() in REDACT_KEYS else _sanitize(v))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_sanitize(item) for item in value]
    if isinstance(value, str) and _BEARER_LIKE.match(value):
        return _REDACTED
    return value


def kv(fields: dict[str, Any]) -> str:
    """Render {field: value} as `key=value` pairs (redacted, log-safe)."""
    safe = _sanitize(fields)
    parts = []
    for key, value in safe.items():
        if value is None:
            continue
        rendered = str(value)
        if any(ch.isspace() for ch in rendered):
            rendered = repr(rendered)
        parts.append(f"{key}={rendered}")
    return " ".join(parts)


def log_event(logger: logging.Logger, message: str, **fields: Any) -> None:
    """Log `message` plus redacted key=value fields at INFO."""
    logger.info("%s %s", message, kv(fields))


def log_warn(logger: logging.Logger, message: str, **fields: Any) -> None:
    """Log `message` plus redacted key=value fields at WARNING."""
    logger.warning("%s %s", message, kv(fields))


class KeyValueFormatter(logging.Formatter):
    """Formatter for plain key=value log records (spec section 37)."""

    def format(self, record: logging.LogRecord) -> str:
        level = record.levelname
        return f"{level} {record.getMessage()}"


def configure_logging() -> None:
    """Configure the sentinelgate logger once at startup (idempotent)."""
    logger = logging.getLogger("sentinelgate")
    if logger.handlers:  # already configured
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(KeyValueFormatter())
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
