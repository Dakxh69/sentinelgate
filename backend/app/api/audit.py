"""Administrative audit trail querying endpoints.

Enforces ADMIN role requirement and rate limiting. Provides paginated,
filterable access to immutable security audit logs.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import require_role
from app.models import ADMIN, User
from app.schemas.audit import AuditEventOut, AuditPage
from app.services.rate_limit_service import enforce_user_rate_limit

router = APIRouter(prefix="/admin", tags=["audit"])


@router.get("/audit", response_model=AuditPage)
def list_audit(
    _admin: Annotated[User, Depends(enforce_user_rate_limit)],
    _role_admin: Annotated[User, Depends(require_role(ADMIN))],
    db: Session = Depends(get_db),
    decision: str | None = Query(default=None, max_length=16),
    user_id: int | None = Query(default=None),
    path_prefix: str | None = Query(default=None, max_length=255),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> AuditPage:
    """Paginated audit events, newest first. ADMIN only."""
    from app.services.audit_service import query_events

    rows, total = query_events(
        db,
        decision=decision,
        user_id=user_id,
        path_prefix=path_prefix,
        limit=limit,
        offset=offset,
    )
    return AuditPage(
        items=[
            AuditEventOut(
                id=e.id,
                request_id=e.request_id,
                timestamp=e.timestamp.isoformat() if e.timestamp else None,
                user_id=e.user_id,
                role=e.role,
                source_ip=e.source_ip,
                method=e.method,
                path=e.path,
                decision=e.decision,
                risk_score=e.risk_score,
                detected_categories=e.detected_categories,
                reason=e.reason,
                response_status=e.response_status,
                forwarded=bool(getattr(e, "forwarded", True)),
            )
            for e in rows
        ],
        total=total,
        limit=limit,
        offset=offset,
    )
