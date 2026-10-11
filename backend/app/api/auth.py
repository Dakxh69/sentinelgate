"""Authentication API endpoints: registration and credential verification.

Guarded by per-IP rate limiting to prevent brute-force attacks.
All login attempts produce audit events (ALLOW for success, BLOCK for failed attempts).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from app.core.errors import SentinelGateError

from app.core.database import get_db
from app.schemas.auth import LoginBody, RegisterBody, TokenBody
from app.schemas.user import UserOut
from app.services.auth_service import login, register
from app.services.rate_limit_service import enforce_ip_rate_limit

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/register",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(enforce_ip_rate_limit)],
    responses={
        409: {
            "model": UserOut,
            "description": "Email or username already registered",
        },
    },
)
def register_route(body: RegisterBody, db: Session = Depends(get_db)) -> UserOut:
    """Register a new user account with default USER role."""
    return register(db, body)


@router.post(
    "/login",
    response_model=TokenBody,
    dependencies=[Depends(enforce_ip_rate_limit)],
)
def login_route(body: LoginBody, request: Request, db: Session = Depends(get_db)) -> TokenBody:
    """Authenticate with email and password to receive a signed JWT bearer token."""
    from app.services.audit_service import record_auth_event

    try:
        token, user = login(db, body)
    except SentinelGateError:
        record_auth_event(
            request, user=None, success=False, response_status=401, db=db
        )
        raise
    record_auth_event(request, user=user, success=True, response_status=200, db=db)
    return token
