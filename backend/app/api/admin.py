"""Administrative policy listing endpoints.

ADMIN role required. Provides overview of all configured security gateway policies.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import require_role
from app.models import ADMIN, Policy, User
from app.services.rate_limit_service import enforce_user_rate_limit

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/policies")
def list_policies(
    _rate_limited: Annotated[User, Depends(enforce_user_rate_limit)],
    _admin: Annotated[User, Depends(require_role(ADMIN))],
    db: Session = Depends(get_db),
) -> dict:
    """ADMIN only. Returns all configured security gateway policies."""
    rows = db.query(Policy).order_by(Policy.id).all()
    return {
        "policies": [
            {
                "id": p.id,
                "name": p.name,
                "role": p.role,
                "path_pattern": p.path_pattern,
                "http_method": p.http_method,
                "sensitive_required": p.sensitive_required,
                "minimum_risk": p.minimum_risk,
                "action": p.action,
                "enabled": p.enabled,
                "created_at": p.created_at.isoformat() if p.created_at else None,
            }
            for p in rows
        ],
    }
