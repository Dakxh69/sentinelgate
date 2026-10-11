"""Day 6 security tests (R5, spec section 35 — all ten items).

Each numbered test maps to §35.1–§35.10. Plus the two "also" checks:
generic 500 body (no stack traces) and secret redaction in logs (§2.5/§37,
verified once more here per the day-06 spec).
"""

from __future__ import annotations

import logging

import pytest

from app.core.config import reset_settings_cache

REGISTER_BODY = {
    "username": "secuser",
    "email": "secuser@example.com",
    "password": "strong-password",
}


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, body: dict) -> str:
    reg = client.post("/auth/register", json=body)
    assert reg.status_code == 201, reg.text
    login_response = client.post(
        "/auth/login", json={"email": body["email"], "password": body["password"]}
    )
    assert login_response.status_code == 200, login_response.text
    return login_response.json()["access_token"]


# --------------------------------------------------------------------------- #
# §35.1 — passwords never stored plaintext (argon2)
# --------------------------------------------------------------------------- #


def test_password_stored_as_argon2_hash(client, db_session):
    _register_and_login(client, REGISTER_BODY)
    from app.models import User

    user = db_session.query(User).filter(User.username == "secuser").first()
    assert user is not None
    assert user.password_hash.startswith("$argon2")
    assert user.password_hash != REGISTER_BODY["password"]


# --------------------------------------------------------------------------- #
# §35.2 — invalid/expired JWTs cannot reach protected endpoints
# --------------------------------------------------------------------------- #


def test_invalid_jwt_rejected_401(client):
    response = client.get("/protected/data", headers=_auth("not-a-real-jwt"))
    assert response.status_code == 401
    assert response.json()["error"] == "AUTHENTICATION_FAILED"


def test_expired_jwt_rejected_401(client, monkeypatch):
    from app.core.security import encode_token
    from app.core.config import get_settings, reset_settings_cache

    # Mint a token with an expiration in the past.
    monkeypatch.setenv("JWT_EXPIRATION_MINUTES", "-1")
    reset_settings_cache()
    try:
        from app.core.config import Settings
        import time

        import jwt as pyjwt

        settings = Settings(JWT_SECRET="test-secret-not-a-real-secret-32bytes!")
        token = pyjwt.encode(
            {
                "sub": "1",
                "role": "USER",
                "iat": time.time() - 10_000,
                "exp": time.time() - 5_000,
            },
            settings.JWT_SECRET,
            algorithm="HS256",
        )
        response = client.get("/protected/data", headers=_auth(token))
        assert response.status_code == 401
        assert response.json()["error"] == "AUTHENTICATION_FAILED"
    finally:
        monkeypatch.delenv("JWT_EXPIRATION_MINUTES", raising=False)
        reset_settings_cache()


def test_wrong_signature_jwt_rejected_401(client):
    import jwt as pyjwt
    import time

    other = pyjwt.encode(
        {"sub": "1", "role": "USER", "exp": time.time() + 60},
        "a-completely-different-secret",
        algorithm="HS256",
    )
    response = client.get("/protected/data", headers=_auth(other))
    assert response.status_code == 401


# --------------------------------------------------------------------------- #
# §35.3 — USER/GUEST cannot access admin endpoints (403)
# --------------------------------------------------------------------------- #


def test_user_cannot_access_admin_endpoints(client, db_session):
    token = _register_and_login(client, REGISTER_BODY)
    for method, path in (
        ("GET", "/admin/audit"),
        ("GET", "/admin/policies"),
        ("POST", "/admin/policies"),
        ("PUT", "/admin/policies/1"),
        ("DELETE", "/admin/policies/1"),
    ):
        response = getattr(client, method.lower())(path, headers=_auth(token))
        assert response.status_code == 403, (method, path, response.status_code)


def test_guest_cannot_access_admin_endpoints(client, db_session):
    from app.models import User
    from argon2 import PasswordHasher

    guest = User(
        username="secguest",
        email="secguest@example.com",
        password_hash=PasswordHasher().hash("guest-pass-123"),
        role="GUEST",
        is_active=True,
    )
    db_session.add(guest)
    db_session.commit()
    login_response = client.post(
        "/auth/login",
        json={"email": "secguest@example.com", "password": "guest-pass-123"},
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    response = client.get("/admin/audit", headers=_auth(token))
    assert response.status_code == 403


# --------------------------------------------------------------------------- #
# §35.4 — rate limits hold under repeated requests
# --------------------------------------------------------------------------- #


def test_rate_limit_holds_under_repeated_requests(client, db_session, monkeypatch, backend_url):
    token = _register_and_login(client, REGISTER_BODY)
    monkeypatch.setenv("RATE_LIMIT_REQUESTS", "5")
    reset_settings_cache()
    try:
        codes = [
            client.get("/protected/data", headers=_auth(token)).status_code
            for _ in range(30)
        ]
        late = codes[6:]  # everything past the limit stays rejected
        assert all(code == 429 for code in late), codes
        assert codes[:5] == [200] * 5 or codes[:5] == [200, 200, 200, 200, 200]
    finally:
        monkeypatch.delenv("RATE_LIMIT_REQUESTS", raising=False)
        reset_settings_cache()


# --------------------------------------------------------------------------- #
# §35.5 — sensitive values never in audit rows or logs
# --------------------------------------------------------------------------- #


def test_sensitive_values_absent_from_audit_and_logs(
    client, db_session, caplog, monkeypatch
):
    from app.models import AuditEvent

    token = _register_and_login(client, REGISTER_BODY)

    # Seed the default policies and let the upload be blocked — audit BLOCK
    # rows must still hold only categories, never raw values (§20/§35.5).
    from app.db.seed import DEFAULT_POLICIES
    from app.models import Policy

    for spec in DEFAULT_POLICIES:
        db_session.add(Policy(**spec))
    db_session.commit()

    secrets_in_request = {
        "password": "super-secret-password-99",
        "authorization": "Bearer eyJfake.token.value",
        "card": "4532015112830366",
        "aadhaar": "234123412345",
        "key_value": "api_key=sk-live-abcdef1234567890",
        "password_field": "password: hunter2bright",
    }

    with caplog.at_level(logging.INFO, logger="sentinelgate"):
        response = client.post(
            "/protected/upload", json=secrets_in_request, headers=_auth(token)
        )
    assert response.status_code == 403

    # DB rows: categories only.
    rows = db_session.query(AuditEvent).order_by(AuditEvent.id.desc()).limit(5).all()
    for row in rows:
        serialized = str(row.__dict__)
        for secret in secrets_in_request.values():
            # The bearer prefix is dropped before any assertion below.
            if secret.startswith("Bearer "):
                secret = secret[len("Bearer "):]
            assert secret not in serialized, secret

    # Logs: none of the raw values appear anywhere.
    log_text = "\n".join(record.getMessage() for record in caplog.records)
    for secret in secrets_in_request.values():
        if secret.startswith("Bearer "):
            secret = secret[len("Bearer "):]
        assert secret not in log_text, secret

    # Categories did land in the audit row(s), proving detection ran.
    categories: set[str] = set()
    for row in rows:
        categories.update(row.detected_categories or [])
    assert "PASSWORD" in categories, categories
    assert "API_KEY" in categories


# --------------------------------------------------------------------------- #
# §35.6 — internal backend not publicly exposed
# --------------------------------------------------------------------------- #


def test_gateway_returns_404_for_internal_paths(client):
    response = client.get("/internal/data")
    assert response.status_code == 404

    response = client.post("/internal/upload", json={"x": "y"})
    assert response.status_code == 404


def test_compose_backend_publishes_no_ports():
    """Static compose check: the backend service must have no `ports:` block."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[2]
    compose = (root / "docker-compose.yml").read_text()
    # crude YAML service-block split: backend's block contains no "ports:"
    import re

    match = re.search(r"^  backend:\n(.*?)^(?=  \w|  gateway|\w)", compose, re.M | re.S)
    assert match is not None, "backend service missing from docker-compose.yml"
    backend_block = match.group(1)
    assert re.search(r"^\s*ports:", backend_block, re.M) is None


# --------------------------------------------------------------------------- #
# §35.7 — invalid policy configuration never defaults to ALLOW
# --------------------------------------------------------------------------- #


def test_corrupt_policy_action_is_treated_as_block_not_allow(client, db_session):
    from app.db.seed import DEFAULT_POLICIES
    from app.models import ADMIN, Policy, User
    from argon2 import PasswordHasher

    for spec in DEFAULT_POLICIES:
        db_session.add(Policy(**spec))
    # Corrupt rule: unknown action, matches everything for ADMIN uploads.
    db_session.add(
        Policy(
            name="corrupt-rule",
            role=ADMIN,
            path_pattern="/protected/*",
            sensitive_required=True,
            minimum_risk=0.1,
            action="MAYBE",
        )
    )
    db_session.add(
        User(
            username="corruptadmin",
            email="corruptadmin@example.com",
            password_hash=PasswordHasher().hash("admin-pass-123"),
            role=ADMIN,
            is_active=True,
        )
    )
    db_session.commit()

    login_response = client.post(
        "/auth/login",
        json={"email": "corruptadmin@example.com", "password": "admin-pass-123"},
    )
    token = login_response.json()["access_token"]
    response = client.post(
        "/protected/upload",
        json={"note": "aadhaar 234123412345 present"},
        headers=_auth(token),
    )
    # A corrupt action fails closed: BLOCK (or REVIEW) — never 200/forwarded.
    assert response.status_code in (403, 500), response.text
    if response.status_code == 403:
        assert response.json()["error"] == "DLP_POLICY_BLOCK"
    if response.status_code == 500:
        assert response.json()["error"] == "INTERNAL_SECURITY_ERROR"


# --------------------------------------------------------------------------- #
# §35.8 — DLP engine failure does not default to ALLOW
# --------------------------------------------------------------------------- #


def test_failing_dlp_engine_rejects_request(client, db_session, monkeypatch):
    from app.services.dlp_service import DLPEngineError

    import app.services.dlp_pipeline as dlp_pipeline

    def broken(request, body, **kwargs):
        raise DLPEngineError("engine binary corrupt")

    monkeypatch.setattr(dlp_pipeline, "inspect_request", broken)
    token = _register_and_login(client, REGISTER_BODY)
    response = client.post("/protected/upload", json={"x": "y"}, headers=_auth(token))
    assert response.status_code in (403, 500)
    assert response.json()["error"] != "ALLOW"
    assert response.status_code in (403, 500)


def test_missing_dlp_engine_binary_fails_closed(client, db_session, monkeypatch):
    """Point DLP_ENGINE_PATH at a nonexistent binary — the request is rejected."""
    from app.core.config import reset_settings_cache

    monkeypatch.setenv("DLP_ENGINE_PATH", "/definitely/not/a/binary")
    reset_settings_cache()
    try:
        token = _register_and_login(client, REGISTER_BODY)
        response = client.post("/protected/upload", json={"x": "y"}, headers=_auth(token))
        assert response.status_code in (403, 500), response.text
        assert response.json()["error"] in (DLP_POLICY_BLOCK := "DLP_POLICY_BLOCK", "INTERNAL_SECURITY_ERROR")
    finally:
        monkeypatch.delenv("DLP_ENGINE_PATH", raising=False)
        reset_settings_cache()


# --------------------------------------------------------------------------- #
# §35.9 — SQL is ORM/parameterized only (grep + ORM tests)
# --------------------------------------------------------------------------- #


def test_no_string_built_sql_in_app_code():
    """Static grep: no f-strings/concatenated text(\"...\") query building."""
    import pathlib
    import re

    app_dir = pathlib.Path(__file__).resolve().parents[1] / "app"
    offenders: list[str] = []
    pattern = re.compile(r"text\(\s*f[\"']")  # text(f"...") string-built SQL
    for path in app_dir.rglob("*.py"):
        if "migrations" in str(path):
            continue
        if pattern.search(path.read_text(errors="replace")):
            offenders.append(str(path))
    assert offenders == []


def test_audit_filter_is_parameterized(client, db_session):
    """A filter value that would break string-built SQL stays inert (ORM)."""
    from argon2 import PasswordHasher

    from app.models import ADMIN, User

    db_session.add(
        User(
            username="sqladmin",
            email="sqladmin@example.com",
            password_hash=PasswordHasher().hash("admin-pass-123"),
            role=ADMIN,
            is_active=True,
        )
    )
    db_session.commit()
    login_response = client.post(
        "/auth/login",
        json={"email": "sqladmin@example.com", "password": "admin-pass-123"},
    )
    token = login_response.json()["access_token"]
    # Classic injection payload as a filter — must be an inert parameter.
    response = client.get(
        "/admin/audit?path_prefix=%27%20OR%201%3D1%20--",
        headers=_auth(token),
    )
    assert response.status_code == 200
    assert "items" in response.json()


# --------------------------------------------------------------------------- #
# §35.10 — CORS not unrestricted
# --------------------------------------------------------------------------- #


def test_cors_disabled_by_default(client, monkeypatch):
    from app.core.config import get_settings

    monkeypatch.delenv("CORS_ALLOWED_ORIGINS", raising=False)
    reset_settings_cache()
    # The ASGI app instance under test was built with empty env → no CORS
    # middleware; a preflight from any origin gets no allow-origin header.
    response = client.options(
        "/protected/data",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
    )
    assert response.headers.get("access-control-allow-origin") in (None, "")
    assert response.status_code in (400, 404, 405)


def test_cors_explicit_origins_only(client, monkeypatch):
    from app.core.config import get_settings, reset_settings_cache

    monkeypatch.setenv(
        "CORS_ALLOWED_ORIGINS", "https://allow.example,https://ops.example"
    )
    reset_settings_cache()

    # Rebuild a minimal app instance with this setting to check middleware
    # behavior (the main module cached its install at first import).
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.testclient import TestClient

    app = FastAPI()

    @app.get("/x")
    def x():
        return {"ok": True}

    origins = get_settings().cors_origins()
    assert origins == ["https://allow.example", "https://ops.example"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=False,
        allow_methods=["GET"],
        allow_headers=["Authorization"],
    )
    local_client = TestClient(app)
    allowed = local_client.get("/x", headers={"Origin": "https://allow.example"})
    assert allowed.headers.get("access-control-allow-origin") == "https://allow.example"
    options = local_client.options(
        "/x",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "GET",
        },
    )
    # Disallowed origin gets no allow-origin grant on the preflight.
    assert options.headers.get("access-control-allow-origin") != "https://ops.example"
    assert "https://evil.example" != (options.headers.get("access-control-allow-origin") or "")


# --------------------------------------------------------------------------- #
# "also": no stack traces to clients; secrets redacted in logs (Day 3 again)
# --------------------------------------------------------------------------- #


def test_generic_500_body_no_stack_trace(client, db_session, monkeypatch):
    import app.main as app_module
    from fastapi.testclient import TestClient

    # Force an unhandled exception inside a temporary test route.
    @app_module.app.get("/_test/boom")
    def _boom():  # pragma: no cover - test hook
        raise RuntimeError("internal blowup with sensitive detail")

    with TestClient(app_module.app, raise_server_exceptions=False) as c:
        response = c.get("/_test/boom")
    assert response.status_code == 500
    body = response.json()
    assert body["error"] == "INTERNAL_SECURITY_ERROR"
    assert "RuntimeError" not in response.text
    assert "blowup" not in response.text

    # Clean the test route out so other tests are unaffected.
    app_module.app.router.routes = [
        r for r in app_module.app.router.routes if getattr(r, "path", None) != "/_test/boom"
    ]


def test_logs_never_carry_authorization_header(client, caplog):
    token = _register_and_login(client, REGISTER_BODY)
    with caplog.at_level(logging.INFO, logger="sentinelgate"):
        client.get("/protected/data", headers={**_auth(token), "X-Anything": "fine"})
    log_text = "\n".join(record.getMessage() for record in caplog.records)
    assert token not in log_text
    assert "Bearer " not in log_text
