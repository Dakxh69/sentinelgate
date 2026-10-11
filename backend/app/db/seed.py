"""Database initialization seed script.

Provisions initial environment:
  - Default administrative and standard user accounts (argon2-hashed credentials from env)
  - Default baseline Zero-Trust gateway security policies

Features:
  - Strict secret validation: Fails if ADMIN_PASSWORD or SEED_USER_PASSWORD are not provided
  - Idempotent: Re-executing does not duplicate existing users or policies

Usage:
    ADMIN_PASSWORD=... SEED_USER_PASSWORD=... python -m app.db.seed
"""

from __future__ import annotations

import sys

from sqlalchemy import select

from app.core.database import SessionLocal
from app.core.security import hash_password
from app.models import ADMIN, USER, Policy, User

DEFAULT_POLICIES: list[dict[str, object]] = [
    {
        "name": "baseline-allow",
        "role": None,
        "path_pattern": "/*",
        "http_method": None,
        "sensitive_required": False,
        "minimum_risk": 0.0,
        "action": "ALLOW",
        "enabled": True,
    },
    {
        "name": "block-user-upload-sensitive",
        "role": "USER",
        "path_pattern": "/protected/upload",
        "http_method": None,
        "sensitive_required": True,
        "minimum_risk": 0.5,
        "action": "BLOCK",
        "enabled": True,
    },
    {
        "name": "review-admin-upload-sensitive",
        "role": "ADMIN",
        "path_pattern": "/protected/upload",
        "http_method": None,
        "sensitive_required": True,
        "minimum_risk": 0.5,
        "action": "REVIEW",
        "enabled": True,
    },
]


# The seeded admin has to be reachable through the API: /auth/register and
# /auth/login validate the address with EmailStr (email-validator), which
# rejects special-use domains (.local, .test, .invalid, ...). RFC 6761 reserves
# the ".example" TLD but deliberately keeps it acceptable to applications, so an
# address here passes validation while never being a routable mailbox.
ADMIN_EMAIL = "admin@sentinelgate.example"


def seed(db_session) -> dict[str, int]:  # type: ignore[no-untyped-def]
    """Run the seed inside the given session; returns created-object counts."""
    created = {"users": 0, "policies": 0}

    if db_session.scalar(select(User).where(User.username == "admin")) is None:
        admin = User(
            username="admin",
            email=ADMIN_EMAIL,
            password_hash=hash_password(_required_password("ADMIN_PASSWORD")),
            role=ADMIN,
            is_active=True,
        )
        db_session.add(admin)
        created["users"] += 1

    if db_session.scalar(select(User).where(User.username == "daksh")) is None:
        user = User(
            username="daksh",
            email="daksh@example.com",
            password_hash=hash_password(_required_password("SEED_USER_PASSWORD")),
            role=USER,
            is_active=True,
        )
        db_session.add(user)
        created["users"] += 1

    for spec in DEFAULT_POLICIES:
        name = str(spec["name"])
        if db_session.scalar(select(Policy).where(Policy.name == name)) is None:
            db_session.add(Policy(**spec))  # type: ignore[arg-type]
            created["policies"] += 1

    db_session.commit()
    return created


def _required_password(env_var: str) -> str:
    from app.core.config import get_settings

    value = getattr(get_settings(), env_var, None)
    if not value:
        raise SystemExit(
            f"refusing to seed: {env_var} is not set "
            "(credentials are never hardcoded, spec section 22)"
        )
    return str(value)


def main() -> int:
    with SessionLocal() as session:
        created = seed(session)
    print(
        f"seed complete: {created['users']} user(s) created, "
        f"{created['policies']} policy/policies created"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
