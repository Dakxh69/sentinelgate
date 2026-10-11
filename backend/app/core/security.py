"""Security helpers: Argon2id password hashing and JWT token management.

Passwords are exclusively hashed using Argon2id with salt and memory-hard parameters.
JWT tokens are signed via HMAC-SHA256 (HS256) and strictly expire.
Tokens encapsulate claims (subject ID, role, issued at, expiration) without sensitive payload.
"""

from __future__ import annotations

import time

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from app.core.config import get_settings

_hasher = PasswordHasher()  # defaults: argon2id, 64 MiB, t=3, p=4


def hash_password(plain: str) -> str:
    """Hash a password with Argon2id."""
    return _hasher.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Constant-time Argon2 verification."""
    try:
        return _hasher.verify(hashed, plain)
    except (VerifyMismatchError, ValueError):
        return False


def encode_token(user_id: str, role: str) -> str:
    """Build a signed JWT (HS256) with sub + role + iat + exp."""
    settings = get_settings()
    now = time.time()
    payload = {
        "sub": user_id,
        "role": role,
        "iat": now,
        "exp": now + settings.JWT_EXPIRATION_MINUTES * 60,
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")


def decode_token(token: str) -> dict:
    """Verify signature + expiry. Raises jwt.PyJWTError on any failure."""
    settings = get_settings()
    return jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
