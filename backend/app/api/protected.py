"""Protected gateway endpoints.

Routes enforce authentication and RBAC before evaluating the Zero-Trust security pipeline.
Allowed requests are proxied upstream to the internal microservice; policy blocks and
reviews halt prior to forwarding.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response

from app.core.dependencies import get_current_user, require_role
from app.core.database import get_db
from app.models import ADMIN, User, USER
from app.schemas.user import UserOut
from app.services.gateway_service import handle_protected

router = APIRouter(prefix="/protected", tags=["protected"])


@router.get("/profile", response_model=UserOut)
def profile(
    current_user: Annotated[User, Depends(get_current_user)],
) -> UserOut:
    """Caller's own profile."""
    from app.services.auth_service import user_out

    return user_out(current_user)


@router.get("/data")
async def protected_data(
    request: Request,
    current_user: Annotated[User, Depends(require_role(USER, ADMIN))],
    db: Annotated[object, Depends(get_db)],
) -> Response:
    """Protected resource for authenticated users."""
    return await handle_protected(request, current_user=current_user, db=db)


@router.post("/upload")
async def protected_upload(
    request: Request,
    current_user: Annotated[User, Depends(require_role(USER, ADMIN))],
    db: Annotated[object, Depends(get_db)],
) -> Response:
    """Protected file and data upload endpoint evaluated by DLP scanner."""
    return await handle_protected(request, current_user=current_user, db=db)
