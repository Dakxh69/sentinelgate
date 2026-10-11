"""Role-based authorization and log redaction test suite."""

from __future__ import annotations

import pytest

REGISTER_BODY = {
    "username": "authuser",
    "email": "authuser@example.com",
    "password": "strong-password",
}


def _login(client, body=REGISTER_BODY):
    login_response = client.post(
        "/auth/login",
        json={"email": body["email"], "password": body["password"]},
    )
    assert login_response.status_code == 200, login_response.text
    return login_response.json()["access_token"]


def _register_and_login(client, body=REGISTER_BODY):
    register_response = client.post("/auth/register", json=body)
    assert register_response.status_code == 201, register_response.text
    token = _login(client, body)
    return {"user": register_response.json(), "token": token}


def _auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def user_auth(client, backend_url):
    return _register_and_login(client)


@pytest.fixture()
def admin_auth(client, db_session, backend_url):
    """Promote the registered user to ADMIN directly in the DB (no admin API)."""
    from app.models import User

    auth = _register_and_login(client)
    user = db_session.get(User, auth["user"]["id"])
    user.role = "ADMIN"
    db_session.commit()
    # Re-login so the token carries the ADMIN role claim.
    return {"user": {**auth["user"], "role": "ADMIN"}, "token": _login(client)}


@pytest.fixture()
def guest_auth(client, db_session):
    """Create a GUEST user directly in the DB (Day 2 R5)."""
    from app.core.security import hash_password
    from app.models import User

    guest = User(
        username="guest",
        email="guest@example.com",
        password_hash=hash_password("guest-password"),
        role="GUEST",
        is_active=True,
    )
    db_session.add(guest)
    db_session.commit()
    login_response = client.post(
        "/auth/login",
        json={"email": "guest@example.com", "password": "guest-password"},
    )
    assert login_response.status_code == 200
    return {"user": guest, "token": login_response.json()["access_token"]}


# ------------------------------------------- R6 protected endpoints (§34 authz)


def test_user_accesses_profile_200(client, user_auth):
    response = client.get("/protected/profile", headers=_auth_header(user_auth["token"]))
    assert response.status_code == 200
    assert response.json()["username"] == "authuser"


def test_guest_accesses_profile_200(client, guest_auth):
    response = client.get("/protected/profile", headers=_auth_header(guest_auth["token"]))
    assert response.status_code == 200
    assert response.json()["role"] == "GUEST"


def test_user_accesses_protected_data_200(client, user_auth):
    response = client.get("/protected/data", headers=_auth_header(user_auth["token"]))
    assert response.status_code == 200
    # Day 6: forwarding is live — the response comes from the internal backend
    # (stage marker updated from the Day 5 staging value).
    assert response.json()["stage"] == "forwarded"


def test_guest_accesses_protected_data_403(client, guest_auth):
    response = client.get("/protected/data", headers=_auth_header(guest_auth["token"]))
    assert response.status_code == 403
    body = response.json()
    assert body["error"] == "AUTHORIZATION_FAILED"
    assert body["message"] == "Insufficient permissions"


def test_guest_cannot_upload_403(client, guest_auth):
    response = client.post(
        "/protected/upload", headers=_auth_header(guest_auth["token"])
    )
    assert response.status_code == 403
    assert response.json()["error"] == "AUTHORIZATION_FAILED"


def test_admin_can_access_protected_data_200(client, admin_auth):
    response = client.get("/protected/data", headers=_auth_header(admin_auth["token"]))
    assert response.status_code == 200


def test_admin_can_upload_200(client, admin_auth):
    response = client.post(
        "/protected/upload", headers=_auth_header(admin_auth["token"])
    )
    assert response.status_code == 200


# --------------------------------------------------- R7 admin endpoints (§35.3)


def test_user_hits_admin_policies_403(client, user_auth):
    response = client.get("/admin/policies", headers=_auth_header(user_auth["token"]))
    assert response.status_code == 403
    assert response.json()["error"] == "AUTHORIZATION_FAILED"


def test_guest_hits_admin_policies_403(client, guest_auth):
    response = client.get("/admin/policies", headers=_auth_header(guest_auth["token"]))
    assert response.status_code == 403


def test_admin_hits_admin_policies_200(client, admin_auth, db_session):
    # Seed the default policies inside the test DB (the suite uses a fresh
    # schema per test; the seed script targets the real dev database).
    from app.db.seed import DEFAULT_POLICIES
    from app.models import Policy

    db_session.add_all([Policy(**spec) for spec in DEFAULT_POLICIES])
    db_session.commit()

    response = client.get("/admin/policies", headers=_auth_header(admin_auth["token"]))
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body["policies"], list)
    names = {p["name"] for p in body["policies"]}
    assert "baseline-allow" in names
    assert "block-user-upload-sensitive" in names


def test_admin_audit_returns_paginated_page(client, admin_auth):
    """Day 3: /admin/audit is paginated ({items,total,limit,offset})."""
    response = client.get("/admin/audit", headers=_auth_header(admin_auth["token"]))
    assert response.status_code == 200
    body = response.json()
    assert set(body.keys()) == {"items", "total", "limit", "offset"}


# ------------------------------------- spec 35.2: invalid JWT cannot access


def test_invalid_jwt_cannot_access_protected_or_admin(client):
    for path in ("/protected/profile", "/protected/data", "/admin/policies"):
        response = client.get(path, headers=_auth_header("garbage-token"))
        assert response.status_code == 401, path
        assert response.json()["error"] == "AUTHENTICATION_FAILED"


# ------------------------------- spec 2.5 / 37: no secrets in logs (caplog)


def test_no_secrets_in_logs(client, user_auth, caplog):
    import logging

    with caplog.at_level(logging.DEBUG):
        client.post(
            "/auth/login",
            json={"email": REGISTER_BODY["email"], "password": "strong-password"},
        )
        client.get(
            "/protected/profile", headers=_auth_header(user_auth["token"])
        )
        client.get(
            "/protected/data",
            headers={"Authorization": "Bearer deliberately-invalid-token"},
        )

    all_text = " ".join(str(r.getMessage()) for r in caplog.records)
    assert "strong-password" not in all_text
    assert user_auth["token"] not in all_text
    assert "deliberately-invalid-token" not in all_text
    assert "Authorization" not in all_text
