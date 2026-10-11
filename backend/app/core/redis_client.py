"""Redis client factory for rate limiting counters and event metrics."""

from __future__ import annotations

import redis

from app.core.config import get_settings

# Test hook: conftest points this at fakeredis when no real Redis is set.
# Always None in production.
_client_override = None


def create_redis_client() -> redis.Redis:
    """Build a Redis client from settings (or the test override).

    decode_responses=True: we only ever handle text (counters, JSON strings).
    No per-request ping here — connections are established lazily; callers that
    must fail closed (health check, rate limiter) check connectivity explicitly.
    """
    if _client_override is not None:
        return _client_override
    settings = get_settings()
    return redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
