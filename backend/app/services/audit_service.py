"""Audit logging service.

Records immutable audit trails for security decisions:
  - Captures request correlation ID, timestamp, client IP, path, decision, and risk score.
  - Category names are audited without persisting raw sensitive payload data.
  - Feed suspicious-behavior counter in Redis for high-frequency security violations.
"""

from __future__ import annotations

import logging

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.logging import log_warn
from app.models import AuditEvent, User

_logger = logging.getLogger("sentinelgate")

# HTTP rejection status codes tracked by the suspicious behavior monitor
_SECURITY_EVENT_STATUSES = frozenset({401, 403, 429})
_SECURITY_EVENT_TTL_SECONDS = 600


def bump_security_events(request, response_status: int | None) -> None:
    """Increment `security_events:{source_ip}` (TTL 600s) on 401/403/429.

    Called from the audit recording paths so every rejection route (login
    failure, authorization failure, rate-limit block) feeds the same counter.
    Best-effort: a Redis failure never changes the security decision.
    """
    if response_status not in _SECURITY_EVENT_STATUSES:
        return
    source_ip = getattr(request.state, "source_ip", None)
    if not source_ip:
        return
    try:
        from app.core.redis_client import create_redis_client

        client = create_redis_client()
        key = f"security_events:{source_ip}"
        count = client.incr(key)
        if count == 1:
            client.expire(key, _SECURITY_EVENT_TTL_SECONDS)
    except Exception as exc:  # noqa: BLE001 - counter failure must not matter
        log_warn(
            _logger,
            "security_events bump failed (best-effort)",
            source_ip=source_ip,
            error_type=type(exc).__name__,
        )


def record_event(
    request,  # starlette Request (has .state.request_id etc.)
    *,
    decision: str | None,
    risk_score: float | None,
    detected_categories: list[str] | None,
    reason: str | None,
    response_status: int | None,
    db: Session | None,
    user_id: int | None = None,
    role: str | None = None,
    forwarded: bool = True,
) -> None:
    """Insert one audit event. Never raises; best-effort by design.

    Also feeds the suspicious-behavior counter when the recorded
    status is a security-relevant rejection (401/403/429).
    """
    bump_security_events(request, response_status)
    state = request.state
    try:
        event = AuditEvent(
            request_id=getattr(state, "request_id", ""),
            user_id=user_id,
            role=role,
            source_ip=getattr(state, "source_ip", None),
            method=getattr(state, "method", None),
            path=getattr(state, "path", None),
            decision=decision,
            risk_score=risk_score,
            detected_categories=detected_categories,
            reason=reason,
            response_status=response_status,
            forwarded=forwarded,
        )
        if db is not None:
            db.add(event)
            db.commit()
        else:
            # No DB session available (e.g. Redis failure before get_db ran).
            log_warn(
                _logger,
                "audit event not persisted (no db session)",
                request_id=getattr(state, "request_id", None),
                reason=reason,
            )
    except Exception as exc:  # noqa: BLE001 - audit failure must not change the decision
        log_warn(
            _logger,
            "audit write failed (best-effort, decision unchanged)",
            request_id=getattr(state, "request_id", None),
            reason=reason,
            error_type=type(exc).__name__,
        )


def record_auth_event(
    request,
    *,
    user: User | None,
    success: bool,
    response_status: int,
    db: Session,
) -> None:
    """Audit a login attempt (success or uniform AUTHENTICATION_FAILED)."""
    record_event(
        request,
        decision="ALLOW" if success else "BLOCK",
        risk_score=None,
        detected_categories=None,
        reason=None if success else "AUTHENTICATION_FAILED",
        response_status=response_status,
        db=db,
        user_id=user.id if user is not None else None,
        role=user.role if user is not None else None,
        forwarded=True,
    )


def record_authz_event(
    request,
    *,
    user: User,
    response_status: int,
    db: Session,
) -> None:
    """Audit a 403 authorization failure (reason AUTHORIZATION_FAILED)."""
    record_event(
        request,
        decision="BLOCK",
        risk_score=None,
        detected_categories=None,
        reason="AUTHORIZATION_FAILED",
        response_status=response_status,
        db=db,
        user_id=user.id,
        role=user.role,
        forwarded=False,
    )


def query_events(
    db: Session,
    *,
    decision: str | None = None,
    user_id: int | None = None,
    path_prefix: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[AuditEvent], int]:
    """Paginated, newest-first audit listing with optional filters."""
    conditions = []
    if decision is not None:
        conditions.append(AuditEvent.decision == decision)
    if user_id is not None:
        conditions.append(AuditEvent.user_id == user_id)
    if path_prefix is not None:
        conditions.append(AuditEvent.path.like(f"{path_prefix}%"))

    base = select(AuditEvent)
    if conditions:
        base = base.where(*conditions)

    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0
    rows = list(
        db.scalars(
            base.order_by(AuditEvent.id.desc()).limit(limit).offset(offset)
        )
    )
    return rows, int(total)
