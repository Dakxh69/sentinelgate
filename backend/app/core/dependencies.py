"""FastAPI dependencies for authentication and role-based access control (RBAC).

Enforces strict separation:
  - 401 AUTHENTICATION_FAILED: Identity verification failure (missing, invalid, expired token)
  - 403 AUTHORIZATION_FAILED: Insufficient permission (user role not in allowed set)

Fails closed on any ambiguity; sensitive tokens are never logged.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Header, Request, Security
from sqlalchemy.orm import Session

from app.core.database import get_db as _get_db
from app.core.errors import AuthenticationFailed, AuthorizationFailed
from app.core.security import decode_token
from app.models import User

# Re-export so routes import auth + db dependencies from one place.
get_db = _get_db


def get_current_user(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    db: Session = Depends(get_db),
) -> User:
    """Authenticate the caller from the Authorization: Bearer header.

    Any failure raises AuthenticationFailed (401 AUTHENTICATION_FAILED).
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise AuthenticationFailed()
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise AuthenticationFailed()

    try:
        payload = decode_token(token)
    except Exception as exc:  # noqa: BLE001 - any decode failure is 401 (fail closed)
        raise AuthenticationFailed() from exc

    user_id = payload.get("sub")
    if user_id is None:
        raise AuthenticationFailed()
    try:
        parsed_id = int(user_id)
    except (TypeError, ValueError) as exc:
        raise AuthenticationFailed() from exc

    user = db.get(User, parsed_id)
    if user is None or not user.is_active:
        # Unknown or deactivated user: same 401, no enumeration hints.
        raise AuthenticationFailed()
    return user


def require_role(*roles: str):
    """Dependency factory: authorize only the given roles (403 on mismatch)."""

    def _check(
        request: Request,
        current_user: Annotated[User, Security(get_current_user)],
        db: Session = Depends(get_db),
    ) -> User:
        if current_user.role not in roles:
            from app.services.audit_service import record_authz_event

            record_authz_event(
                request, user=current_user, response_status=403, db=db
            )
            raise AuthorizationFailed()
        return current_user

    return _check
