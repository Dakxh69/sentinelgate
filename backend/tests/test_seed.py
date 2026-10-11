"""Seed script tests (Day 1 R6, spec section 22).

The seeded admin must actually be able to log in: its address goes through the
same EmailStr validation as /auth/login, so a special-use domain (the old
``admin@sentinelgate.local``) made the account unusable — every login attempt
returned 422 instead of checking credentials. These tests lock the fix in.
"""

from __future__ import annotations

import pytest


@pytest.fixture()
def seed_passwords(monkeypatch):
    """Give the seed script deterministic credentials and refresh settings."""
    monkeypatch.setenv("ADMIN_PASSWORD", "seed-admin-password-123")
    monkeypatch.setenv("SEED_USER_PASSWORD", "seed-user-password-123")
    from app.core.config import reset_settings_cache

    reset_settings_cache()
    yield
    reset_settings_cache()


def test_seeded_admin_email_passes_login_validation():
    from app.db.seed import ADMIN_EMAIL
    from app.schemas.auth import LoginBody

    # No exception: the seeded address is accepted by the login schema.
    LoginBody(email=ADMIN_EMAIL, password="any-password-123")


def test_seeded_admin_can_log_in_and_reach_admin_endpoint(
    client, db_session, seed_passwords
):
    from app.db.seed import ADMIN_EMAIL, seed
    from app.core.security import decode_token

    created = seed(db_session)
    assert created["users"] == 2, "seed creates the admin and the normal user"
    assert created["policies"] == 3

    login = client.post(
        "/auth/login",
        json={"email": ADMIN_EMAIL, "password": "seed-admin-password-123"},
    )
    assert login.status_code == 200, login.text
    token = login.json()["access_token"]
    assert decode_token(token)["role"] == "ADMIN"

    audit = client.get(
        "/admin/audit?limit=1", headers={"Authorization": f"Bearer {token}"}
    )
    assert audit.status_code == 200, audit.text
    assert set(audit.json()) == {"items", "total", "limit", "offset"}


def test_seed_is_idempotent_for_existing_users(client, db_session, seed_passwords):
    from app.db.seed import seed

    first = seed(db_session)
    second = seed(db_session)
    assert first["users"] == 2
    assert second == {"users": 0, "policies": 0}
