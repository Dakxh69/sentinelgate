"""Policy management CRUD API endpoints.

Exclusively accessible by administrators (ADMIN role required).
Provides creation, update, and deletion of security policies.
All inputs are rigorously validated: actions must be in {ALLOW, BLOCK, REVIEW},
and risk ranges must strictly adhere to [0.0, 1.0].
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import require_role
from app.core.logging import log_event
from app.models import ADMIN, USER, GUEST, Policy, User
from app.services.rate_limit_service import enforce_user_rate_limit

import logging

_logger = logging.getLogger("sentinelgate")

router = APIRouter(prefix="/admin", tags=["policies"])

VALID_ACTIONS = ("ALLOW", "BLOCK", "REVIEW")
VALID_ROLES = (ADMIN, USER, GUEST)


class PolicyIn(BaseModel):
    """Policy create/update payload."""

    name: str
    role: str | None = None
    path_pattern: str | None = None
    http_method: str | None = None
    sensitive_required: bool | None = None
    minimum_risk: float | None = None
    action: str
    enabled: bool = True

    @field_validator("name")
    @classmethod
    def _name_required(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("name is required")
        return value.strip()

    @field_validator("action")
    @classmethod
    def _action_valid(cls, value: str) -> str:
        action = (value or "").strip().upper()
        if action not in VALID_ACTIONS:
            raise ValueError(f"action must be one of {VALID_ACTIONS}")
        return action

    @field_validator("role")
    @classmethod
    def _role_valid(cls, value: str | None) -> str | None:
        if value is None:
            return None
        role = value.strip().upper()
        if role not in VALID_ROLES:
            raise ValueError(f"role must be one of {VALID_ROLES} or null")
        return role

    @field_validator("http_method")
    @classmethod
    def _method_valid(cls, value: str | None) -> str | None:
        if value is None:
            return None
        method = value.strip().upper()
        if not method.isalpha() or len(method) > 16:
            raise ValueError("http_method must be a valid HTTP verb or null")
        return method

    @field_validator("path_pattern")
    @classmethod
    def _path_starts_with_slash(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not value.startswith("/"):
            raise ValueError("path_pattern must start with '/'")
        return value

    @field_validator("minimum_risk")
    @classmethod
    def _risk_in_range(cls, value: float | None) -> float | None:
        if value is None:
            return None
        if not 0.0 <= value <= 1.0:
            raise ValueError("minimum_risk must be within [0.0, 1.0]")
        return value


class PolicyOut(PolicyIn):
    id: int


def _policy_row(policy: Policy) -> dict[str, Any]:
    return {
        "id": policy.id,
        "name": policy.name,
        "role": policy.role,
        "path_pattern": policy.path_pattern,
        "http_method": policy.http_method,
        "sensitive_required": policy.sensitive_required,
        "minimum_risk": policy.minimum_risk,
        "action": policy.action,
        "enabled": policy.enabled,
    }


def _log_change(request: Request, admin: User, change: str, policy: Policy) -> None:
    """Structured log with the acting admin's id — never secrets."""
    log_event(
        _logger,
        f"policy {change}",
        request_id=getattr(request.state, "request_id", None),
        admin_id=admin.id,
        policy_id=policy.id,
        policy_name=policy.name,
        action=policy.action,
    )


@router.post("/policies", status_code=201)
def create_policy(
    payload: PolicyIn,
    request: Request,
    _admin: Annotated[User, Depends(enforce_user_rate_limit)],
    current_admin: Annotated[User, Depends(require_role(ADMIN))],
    db: Session = Depends(get_db),
) -> dict:
    """Create a policy (ADMIN only, 201)."""
    policy = Policy(**payload.model_dump())
    db.add(policy)
    db.commit()
    db.refresh(policy)
    _log_change(request, current_admin, "created", policy)
    return _policy_row(policy)


@router.put("/policies/{policy_id}")
def update_policy(
    policy_id: int,
    payload: PolicyIn,
    request: Request,
    _admin: Annotated[User, Depends(enforce_user_rate_limit)],
    current_admin: Annotated[User, Depends(require_role(ADMIN))],
    db: Session = Depends(get_db),
) -> dict:
    """Replace a policy's fields (ADMIN only, 200; 404 when unknown)."""
    policy = db.get(Policy, policy_id)
    if policy is None:
        _not_found()
    for key, value in payload.model_dump().items():
        setattr(policy, key, value)
    db.commit()
    db.refresh(policy)
    _log_change(request, current_admin, "updated", policy)
    return _policy_row(policy)


@router.delete("/policies/{policy_id}", status_code=204)
def delete_policy(
    policy_id: int,
    request: Request,
    _admin: Annotated[User, Depends(enforce_user_rate_limit)],
    current_admin: Annotated[User, Depends(require_role(ADMIN))],
    db: Session = Depends(get_db),
) -> None:
    """Delete a policy (ADMIN only, 204; 404 when unknown)."""
    policy = db.get(Policy, policy_id)
    if policy is None:
        _not_found()
    db.delete(policy)
    db.commit()
    _log_change(request, current_admin, "deleted", policy)


def _not_found() -> None:
    """Return 404 with the uniform error shape."""
    from fastapi import HTTPException

    raise HTTPException(
        status_code=404,
        detail={"error": "POLICY_NOT_FOUND", "message": "Policy not found"},
    )
