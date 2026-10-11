"""Authentication and credential lifecycle test suite."""

from __future__ import annotations

import time

import jwt
import pytest

from app.core.security import decode_token

REGISTER_BODY = {
    "username": "daksh",
    "email": "daksh@example.com",
    "password": "strong-password",
}


@pytest.fixture()
def registered(client):
    """Register once and return the 201 JSON."""
    response = client.post("/auth/register", json=REGISTER_BODY)
    assert response.status_code == 201
    return response.json()


# ---------------------------------------------------------------- R1 register


def test_register_returns_safe_user_json(client, db_session, registered):
    body = registered
    assert body["username"] == "daksh"
    assert body["email"] == "daksh@example.com"
    assert body["role"] == "USER"
    assert body["is_active"] is True
    assert "password" not in body
    assert "password_hash" not in body

    from app.models import User

    row = db_session.query(User).filter(User.email == "daksh@example.com").one()
    assert row.password_hash.startswith("$argon2"), (
        "password must be stored as an argon2 hash (spec 35.1)"
    )
    assert "strong-password" not in row.password_hash


def test_register_duplicate_email_conflict(client, registered):
    duplicate = dict(REGISTER_BODY, username="other")
    response = client.post("/auth/register", json=duplicate)
    assert response.status_code == 409
    assert response.json()["error"] == "INVALID_REQUEST"
    assert "Email already registered" in response.json()["message"]


def test_register_duplicate_username_conflict(client, registered):
    duplicate = dict(REGISTER_BODY, email="other@example.com")
    response = client.post("/auth/register", json=duplicate)
    assert response.status_code == 409
    assert response.json()["error"] == "INVALID_REQUEST"


@pytest.mark.parametrize(
    "payload",
    [
        {"username": "ab", "email": "x@example.com", "password": "longenough1"},
        {"username": "okname", "email": "not-an-email", "password": "longenough1"},
        {"username": "okname", "email": "x@example.com", "password": "short"},
        {"username": "okname", "email": "x@example.com"},
        {},
    ],
)
def test_register_invalid_payload_422_invalid_request(client, payload):
    response = client.post("/auth/register", json=payload)
    assert response.status_code == 422
    body = response.json()
    assert body["error"] == "INVALID_REQUEST"
    assert "message" in body


# ------------------------------------------------------------------- R2 login


def test_login_valid_returns_bearer_token(client, registered):
    response = client.post(
        "/auth/login",
        json={"email": "daksh@example.com", "password": "strong-password"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert isinstance(body["access_token"], str) and body["access_token"]

    claims = decode_token(body["access_token"])
    assert claims["role"] == "USER"
    assert claims["sub"] == str(registered["id"])


def test_login_wrong_password_uniform_401(client, registered):
    response = client.post(
        "/auth/login",
        json={"email": "daksh@example.com", "password": "wrong-password"},
    )
    assert response.status_code == 401
    assert response.json() == {
        "error": "AUTHENTICATION_FAILED",
        "message": "Invalid credentials",
    }


def test_login_unknown_email_same_401_as_wrong_password(client):
    response = client.post(
        "/auth/login",
        json={"email": "ghost@example.com", "password": "wrong-password"},
    )
    assert response.status_code == 401
    # Identical body to the wrong-password case: no user enumeration (Day 2 R2).
    assert response.json() == {
        "error": "AUTHENTICATION_FAILED",
        "message": "Invalid credentials",
    }


def test_login_deactivated_user_401(client, registered, db_session):
    from app.models import User

    user = db_session.query(User).filter(User.email == "daksh@example.com").one()
    user.is_active = False
    db_session.commit()

    response = client.post(
        "/auth/login",
        json={"email": "daksh@example.com", "password": "strong-password"},
    )
    assert response.status_code == 401
    assert response.json()["error"] == "AUTHENTICATION_FAILED"


# --------------------------------------------------------------- R3 JWT cases


def _make_token(user_id: str, role: str, **overrides) -> str:
    from app.core.config import get_settings

    now = time.time()
    payload = {"sub": user_id, "role": role, "iat": now, **overrides}
    return jwt.encode(payload, get_settings().JWT_SECRET, algorithm="HS256")


def test_expired_jwt_is_rejected(client, registered):
    token = _make_token(str(registered["id"]), "USER", exp=time.time() - 60)
    response = client.get(
        "/protected/profile", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 401
    assert response.json()["error"] == "AUTHENTICATION_FAILED"


def test_tampered_jwt_is_rejected(client, registered):
    token = decode_token  # keep the helper referenced; build a fresh token
    good = _make_token(str(registered["id"]), "USER", exp=time.time() + 600)
    tampered = good[:-4] + ("aaaa" if not good.endswith("aaaa") else "bbbb")
    response = client.get(
        "/protected/profile", headers={"Authorization": f"Bearer {tampered}"}
    )
    assert response.status_code == 401


def test_garbage_jwt_is_rejected(client):
    response = client.get(
        "/protected/profile", headers={"Authorization": "Bearer not.a.jwt"}
    )
    assert response.status_code == 401
    assert response.json()["error"] == "AUTHENTICATION_FAILED"


def test_wrong_secret_jwt_is_rejected(client, registered):
    token = jwt.encode(
        {"sub": str(registered["id"]), "role": "USER", "exp": time.time() + 600},
        "some-other-secret",
        algorithm="HS256",
    )
    response = client.get(
        "/protected/profile", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 401


def test_missing_authorization_header_401(client):
    response = client.get("/protected/profile")
    assert response.status_code == 401
    assert response.json()["error"] == "AUTHENTICATION_FAILED"
