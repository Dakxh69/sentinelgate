"""Rate limiting service.

Implements distributed fixed-window counters in Redis:
  - Per authenticated user: rate_limit:{user_id}:{window}
  - Per client IP (unauthenticated endpoints): rate_limit:ip:{source_ip}:{window}

Uses atomic Redis pipelines with INCR and EXPIRE. Requests exceeding threshold
trigger 429 RATE_LIMIT_EXCEEDED.
Fail-closed guarantee: Any Redis connection failure returns 503 and audits REDIS_UNAVAILABLE.
"""

from __future__ import annotations

import time
from typing import Annotated

from fastapi import Depends, Request
from redis.exceptions import RedisError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.core.errors import SentinelGateError
from app.core.redis_client import create_redis_client
from app.models import User

REASON_RATE_LIMIT = "RATE_LIMIT_EXCEEDED"
REASON_REDIS_UNAVAILABLE = "REDIS_UNAVAILABLE"


class RateLimitExceeded(SentinelGateError):
    """Request #limit+1 in the current window (spec section 12: 429)."""

    status_code = 429
    error_code = REASON_RATE_LIMIT
    message = "Too many requests"


class RateLimiterUnavailable(SentinelGateError):
    """Redis failure — fail closed (spec 2.4): 503, never allow."""

    status_code = 503
    error_code = "INTERNAL_SECURITY_ERROR"
    message = "Rate limiter unavailable"


def _window(now_epoch: float | None = None) -> int:
    settings = get_settings()
    return int((now_epoch if now_epoch is not None else time.time()) // settings.RATE_LIMIT_WINDOW_SECONDS)


def hit(
    redis_client,
    key: str,
    *,
    now_epoch: float | None = None,
) -> int:
    """INCR the counter and EXPIRE it on first increment. Returns the count.

    Raises RedisError on backend failure (callers decide fail-closed policy).
    """
    settings = get_settings()
    window = _window(now_epoch)
    windowed_key = f"{key}:{window}"
    pipeline = redis_client.pipeline(transaction=True)
    pipeline.incr(windowed_key)
    pipeline.expire(windowed_key, settings.RATE_LIMIT_WINDOW_SECONDS + 1)
    count, _ = pipeline.execute()
    return int(count)


def check_count(count: int) -> bool:
    """True when count is within the limit (count <= limit is allowed)."""
    return count <= get_settings().RATE_LIMIT_REQUESTS


def enforce_user_rate_limit(
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
) -> User:
    """FastAPI dependency: per-user fixed window (applied after authn/authz)."""
    _enforce(
        request,
        f"rate_limit:{current_user.id}",
        user_id=current_user.id,
        db=db,
    )
    return current_user


def enforce_user_rate_limit_raw(
    request: Request,
    current_user: User,
    db: Session,
) -> User:
    """Non-dependency form of the per-user limiter for the gateway pipeline.

    Returns the user when the request is within its window. Raises the
    limiter's SentinelGateError (429 RATE_LIMIT_EXCEEDED / 503
    REDIS_UNAVAILABLE) after the rejection has been audited — the gateway
    renders the error response itself and stops before DLP/forwarding.
    """
    _enforce(
        request,
        f"rate_limit:{current_user.id}",
        user_id=current_user.id,
        db=db,
    )
    return current_user


def enforce_ip_rate_limit(
    request: Request,
    db: Session = Depends(get_db),
) -> None:
    """FastAPI dependency: per-IP fixed-window rate limiter for /auth/* routes."""
    _enforce(
        request,
        f"rate_limit:ip:{request.state.source_ip}",
        user_id=None,
        db=db,
    )


def _enforce(request: Request, key: str, *, user_id: int | None, db: Session) -> None:
    from app.services.audit_service import record_event

    try:
        client = create_redis_client()
        count = hit(client, key)
    except RedisError as exc:
        # Fail closed: reject, never allow through an unavailable limiter.
        record_event(
            request,
            decision="BLOCK",
            risk_score=None,
            detected_categories=None,
            reason=REASON_REDIS_UNAVAILABLE,
            response_status=503,
            db=db,
            user_id=user_id,
        )
        raise RateLimiterUnavailable() from exc

    if not check_count(count):
        record_event(
            request,
            decision="BLOCK",
            risk_score=None,
            detected_categories=None,
            reason=REASON_RATE_LIMIT,
            response_status=429,
            db=db,
            user_id=user_id,
        )
        raise RateLimitExceeded()
