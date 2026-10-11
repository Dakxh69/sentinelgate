"""Audit logging integration and security tests."""

from __future__ import annotations

import logging

import pytest

REGISTER_BODY = {
    "username": "audituser",
    "email": "audituser@example.com",
    "password": "super-secret-password-123",
}


@pytest.fixture()
def small_limit(monkeypatch):
    from app.core.config import get_settings, reset_settings_cache

    monkeypatch.setenv("RATE_LIMIT_REQUESTS", "100")
    monkeypatch.setenv("RATE_LIMIT_WINDOW_SECONDS", "60")
    reset_settings_cache()
    yield get_settings()
    monkeypatch.delenv("RATE_LIMIT_REQUESTS", raising=False)
    monkeypatch.delenv("RATE_LIMIT_WINDOW_SECONDS", raising=False)
    reset_settings_cache()


@pytest.fixture()
def user_token(client, small_limit):
    assert client.post("/auth/register", json=REGISTER_BODY).status_code == 201
    login_response = client.post(
        "/auth/login",
        json={"email": REGISTER_BODY["email"], "password": REGISTER_BODY["password"]},
    )
    assert login_response.status_code == 200
    return login_response.json()["access_token"]


@pytest.fixture()
def admin_token(client, small_limit, db_session, user_token):
    from app.models import User

    user = db_session.query(User).filter(User.username == "audituser").one()
    user.role = "ADMIN"
    db_session.commit()
    login_response = client.post(
        "/auth/login",
        json={"email": REGISTER_BODY["email"], "password": REGISTER_BODY["password"]},
    )
    return login_response.json()["access_token"]


def _audit_rows(db_session):
    from app.models import AuditEvent

    return db_session.query(AuditEvent).order_by(AuditEvent.id).all()


# ------------------------------------------- 401 login failures audited


def test_failed_login_produces_audit_row(client, small_limit, db_session):
    response = client.post(
        "/auth/login",
        json={"email": "ghost@example.com", "password": "wrong-password"},
    )
    assert response.status_code == 401

    rows = _audit_rows(db_session)
    assert len(rows) == 1
    row = rows[0]
    assert row.decision == "BLOCK"
    assert row.reason == "AUTHENTICATION_FAILED"
    assert row.response_status == 401
    assert row.user_id is None


def test_successful_login_produces_allow_audit_row(client, small_limit, db_session):
    assert client.post("/auth/register", json=REGISTER_BODY).status_code == 201
    response = client.post(
        "/auth/login",
        json={"email": REGISTER_BODY["email"], "password": REGISTER_BODY["password"]},
    )
    assert response.status_code == 200

    rows = _audit_rows(db_session)
    assert rows[-1].decision == "ALLOW"
    assert rows[-1].reason is None
    assert rows[-1].user_id is not None


# ------------------------------------------- 403 audited


def test_authorization_failure_produces_audit_row(client, small_limit, db_session, user_token):
    response = client.get(
        "/admin/policies", headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 403

    matches = [r for r in _audit_rows(db_session) if r.reason == "AUTHORIZATION_FAILED"]
    assert len(matches) == 1
    row = matches[0]
    assert row.response_status == 403
    assert row.decision == "BLOCK"
    assert row.role == "USER"


# ------------------------------------------- 429 audited


def test_rate_limit_block_produces_audit_row(client, small_limit, db_session, monkeypatch):
    import app.services.rate_limit_service as rls

    assert client.post("/auth/register", json=REGISTER_BODY).status_code == 201
    login_response = client.post(
        "/auth/login",
        json={"email": REGISTER_BODY["email"], "password": REGISTER_BODY["password"]},
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    # First allowed request consumes the IP window's last slot; monkeypatch the
    # user-key check so the next protected request is counted as over-limit.
    monkeypatch.setattr(rls, "check_count", lambda count: count <= 0)
    blocked = client.get(
        "/protected/data", headers={"Authorization": f"Bearer {token}"}
    )
    assert blocked.status_code == 429

    matches = [r for r in _audit_rows(db_session) if r.reason == "RATE_LIMIT_EXCEEDED"]
    assert matches, "429 must be audited with reason RATE_LIMIT_EXCEEDED"
    assert matches[-1].response_status == 429


# ------------------------------------------- request-id correlation (§33)


def test_audit_row_carries_response_request_id(client, small_limit, db_session):
    response = client.post(
        "/auth/login",
        json={"email": "ghost@example.com", "password": "wrong-password"},
        headers={"X-Request-ID": "testcorrelation123"},
    )
    assert response.status_code == 401
    assert response.headers["X-Request-ID"] == "testcorrelation123"

    rows = _audit_rows(db_session)
    assert rows[-1].request_id == "testcorrelation123"


# ------------------------------------------- no secrets in audit (§35.5)


def test_no_password_or_token_in_audit_row_or_logs(client, small_limit, db_session, caplog):
    with caplog.at_level(logging.DEBUG):
        response = client.post(
            "/auth/login",
            json={"email": "ghost@example.com", "password": "super-secret-password-123"},
        )
        assert response.status_code == 401
        token_probe = client.get("/protected/profile")
        assert token_probe.status_code == 401

    rows = _audit_rows(db_session)
    for row in rows:
        serialized = repr(
            (
                row.request_id,
                row.reason,
                row.decision,
                row.path,
                row.method,
                row.source_ip,
            )
        )
        assert "super-secret-password-123" not in serialized
        assert "password" not in (row.reason or "").lower()

    all_log_text = " ".join(str(r.getMessage()) for r in caplog.records)
    assert "super-secret-password-123" not in all_log_text
    assert "Authorization" not in all_log_text


# ------------------------------------------- /admin/audit (ADMIN, paginated)


def test_admin_audit_requires_admin(client, small_limit, user_token):
    response = client.get(
        "/admin/audit", headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 403


def test_admin_audit_paginated(client, small_limit, db_session, admin_token):
    # A couple of events already exist from login; add filters/pagination checks.
    response = client.get(
        "/admin/audit?limit=1&offset=0",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert set(body.keys()) == {"items", "total", "limit", "offset"}
    assert body["limit"] == 1 and body["offset"] == 0
    assert len(body["items"]) == 1
    assert body["total"] >= 1

    page2 = client.get(
        "/admin/audit?limit=1&offset=1",
        headers={"Authorization": f"Bearer {admin_token}"},
    ).json()
    if body["total"] > 1:
        assert page2["items"][0]["id"] != body["items"][0]["id"]


def test_admin_audit_filter_by_decision(client, small_limit, db_session, admin_token):
    response = client.get(
        "/admin/audit?decision=BLOCK",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    for item in response.json()["items"]:
        assert item["decision"] == "BLOCK"
