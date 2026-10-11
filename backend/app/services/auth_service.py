"""Authentication service: registration and login business logic.

Security characteristics:
  - Plaintext passwords are never stored (Argon2id hashing only).
  - Default USER role assigned upon registration.
  - Constant-time verification & uniform 401 error response for invalid credentials
    to prevent username/email enumeration.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import AuthenticationFailed, SentinelGateError
from app.core.security import encode_token, hash_password, verify_password
from app.models import USER, User
from app.schemas.auth import LoginBody, RegisterBody, TokenBody
from app.schemas.user import UserOut


class RegistrationConflict(SentinelGateError):
    """Duplicate email or username conflict."""

    status_code = 409
    error_code = "INVALID_REQUEST"
    message = "Email or username already registered"


def register(db: Session, body: RegisterBody) -> UserOut:
    """Create a new USER account. Raises RegistrationConflict on duplicates."""
    if db.scalar(select(User).where(User.email == body.email)) is not None:
        raise RegistrationConflict("Email already registered")
    if db.scalar(select(User).where(User.username == body.username)) is not None:
        raise RegistrationConflict("Username already registered")

    user = User(
        username=body.username,
        email=body.email,
        password_hash=hash_password(body.password),
        role=USER,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return _user_out(user)


def login(db: Session, body: LoginBody) -> tuple[TokenBody, User]:
    """Authenticate by email + password. Every failure → uniform 401.

    Returns (token, user) so the route can audit the login outcome.
    """
    user = db.scalar(select(User).where(User.email == body.email))
    if (
        user is None
        or not user.is_active
        or not verify_password(body.password, user.password_hash)
    ):
        raise AuthenticationFailed()

    return TokenBody(access_token=encode_token(str(user.id), user.role)), user


def user_out(user: User) -> UserOut:
    """Public shape of a user (no password_hash, ever)."""
    return _user_out(user)


def _user_out(user: User) -> UserOut:
    return UserOut(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role,
        created_at=user.created_at.isoformat(),
        is_active=bool(user.is_active),
    )
