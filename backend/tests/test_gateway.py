"""Day 6 integration tests (R6, spec sections 6/34/49).

Full-pipeline tests against the same codebase, self-contained runner:
- gateway app exercised through FastAPI TestClient (conftest `client`);
- the internal demo backend app run on a real local uvicorn port and reached
  through the production httpx forwarding path (BACKEND_URL points at it);
- SQLite JSON-variant DB + fakeredis by default; real PG/Redis when
  TEST_DATABASE_URL / TEST_REDIS_URL are set (mode printed by conftest).

Scenario coverage (§34): happy path ALLOW→forward, blocked path (§44 step 4),
REVIEW path, rate-limited path, request-ID propagation, fail-closed paths
(redis down → 503, policy engine error → 500, DLP engine failure → 500,
backend unreachable → 502) and the §6 stage-order proof (R1, dummy hooks).
"""

from __future__ import annotations

import pytest

from app.core.config import reset_settings_cache

REGISTER_BODY = {
    "username": "gwuser",
    "email": "gwuser@example.com",
    "password": "strong-password",
}

ADMIN_REGISTER = {
    "username": "gwadmin",
    "email": "gwadmin@example.com",
    "password": "strong-admin-password",
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


def _seed_default_policies(db_session) -> None:
    """Seed the three default §19 policies used by the gateway tests."""
    from app.db.seed import DEFAULT_POLICIES
    from app.models import Policy

    for spec in DEFAULT_POLICIES:
        db_session.add(Policy(**spec))
    db_session.commit()


@pytest.fixture()
def user_token(client, backend_url):
    return _register_and_login(client, REGISTER_BODY)


# --------------------------------------------------------------------------- #
# Happy path (§34: full pipeline ends at the backend, audit records ALLOW)
# --------------------------------------------------------------------------- #


def test_happy_path_forwards_to_internal_backend(client, db_session, user_token, backend_url):
    _seed_default_policies(db_session)

    response = client.get("/protected/data", headers=_auth(user_token))
    assert response.status_code == 200, response.text

    body = response.json()
    # Passed-through internal backend payload (R3) + gateway observability.
    assert body["resource"] == "internal-data"
    assert body["items"] == ["alpha", "beta", "gamma"]
    assert body["detected"] is False
    assert body["stage"] == "forwarded"

    # Audit ALLOW row exists with the pipeline fields (§20/§49).
    from app.models import AuditEvent

    events = db_session.query(AuditEvent).filter(AuditEvent.decision == "ALLOW").all()
    assert any(
        event.method == "GET" and event.path == "/protected/data"
        for event in events
    ), [event.__dict__ for event in events]


def test_upload_happy_path_forwards_body_and_bytes(client, db_session, user_token, backend_url):
    _seed_default_policies(db_session)
    payload = {"note": "totally ordinary note"}

    response = client.post("/protected/upload", json=payload, headers=_auth(user_token))
    assert response.status_code == 200, response.text
    body = response.json()
    # The backend really received the bytes of our body.
    assert body["received_bytes"] > 0


# --------------------------------------------------------------------------- #
# Blocked path (§44 step 4): Aadhaar + API key → 403, backend not called
# --------------------------------------------------------------------------- #


def test_blocked_upload_never_reaches_backend(client, db_session, user_token, backend_url):
    _seed_default_policies(db_session)
    sensitive = {
        "aadhaar": "aadhaar 234123412345",
        "api_key": "api_key=supersecrettoken123",
    }
    response = client.post("/protected/upload", json=sensitive, headers=_auth(user_token))
    assert response.status_code == 403, response.text
    assert response.json()["error"] == "DLP_POLICY_BLOCK"

    from app.models import AuditEvent

    request_id = response.headers["X-Request-ID"]
    allow_row = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.request_id == request_id, AuditEvent.decision == "ALLOW")
        .first()
    )
    assert allow_row is None  # BLOCK short-circuits before forwarding
    event = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.request_id == request_id)
        .order_by(AuditEvent.id.desc())
        .first()
    )
    assert event is not None and event.decision == "BLOCK"
    assert event.risk_score is not None and event.risk_score >= 0.8
    assert set(event.detected_categories or []) >= {"AADHAAR", "API_KEY"}


# --------------------------------------------------------------------------- #
# REVIEW path (§19 C): ADMIN + card → 202, backend not called
# --------------------------------------------------------------------------- #


def test_review_upload_admin_card_202(client, db_session, backend_url):
    from argon2 import PasswordHasher

    from app.models import ADMIN, AuditEvent, User

    db_session.add(
        User(
            username="reviewadmin",
            email="reviewadmin@example.com",
            password_hash=PasswordHasher().hash("admin-pass-123"),
            role=ADMIN,
            is_active=True,
        )
    )
    db_session.commit()
    _seed_default_policies(db_session)

    login_response = client.post(
        "/auth/login",
        json={"email": "reviewadmin@example.com", "password": "admin-pass-123"},
    )
    assert login_response.status_code == 200, login_response.text
    token = login_response.json()["access_token"]

    response = client.post(
        "/protected/upload",
        json={"body": "card 4532015112830366"},
        headers=_auth(token),
    )
    assert response.status_code == 202, response.text
    assert response.json()["decision"] == "REVIEW"

    request_id = response.headers["X-Request-ID"]
    event = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.request_id == request_id, AuditEvent.decision == "REVIEW")
        .first()
    )
    assert event is not None
    allow_row = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.request_id == request_id, AuditEvent.decision == "ALLOW")
        .first()
    )
    assert allow_row is None


# --------------------------------------------------------------------------- #
# Rate-limited path → 429 + audit
# --------------------------------------------------------------------------- #


def test_rate_limited_request_audited(client, db_session, user_token, monkeypatch):
    from app.models import AuditEvent

    monkeypatch.setenv("RATE_LIMIT_REQUESTS", "2")
    reset_settings_cache()
    try:
        codes = [
            client.get("/protected/data", headers=_auth(user_token)).status_code
            for _ in range(4)
        ]
        assert codes == [200, 200, 429, 429], codes
        event = (
            db_session.query(AuditEvent)
            .filter(AuditEvent.reason == "RATE_LIMIT_EXCEEDED")
            .order_by(AuditEvent.id.desc())
            .first()
        )
        assert event is not None
        assert event.response_status == 429
    finally:
        monkeypatch.delenv("RATE_LIMIT_REQUESTS", raising=False)
        reset_settings_cache()


# --------------------------------------------------------------------------- #
# Request-ID propagation end-to-end (§33)
# --------------------------------------------------------------------------- #


def test_request_id_propagates_to_backend_and_audit(client, db_session, user_token, backend_url):
    _seed_default_policies(db_session)
    request_id = "reqid-test-12345678"
    response = client.get(
        "/protected/data",
        headers={**_auth(user_token), "X-Request-ID": request_id},
    )
    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == request_id
    # The internal backend echoed the same id it received from the gateway.
    assert response.json()["request_id"] == request_id

    from app.models import AuditEvent

    event = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.request_id == request_id, AuditEvent.decision == "ALLOW")
        .order_by(AuditEvent.id.desc())
        .first()
    )
    assert event is not None


# --------------------------------------------------------------------------- #
# Fail-closed paths (§2.4/§35.7/§35.8) + backend unavailability (R3)
# --------------------------------------------------------------------------- #


def test_policy_engine_failure_returns_500(client, db_session, user_token, backend_url, monkeypatch):
    _seed_default_policies(db_session)
    import app.services.policy_pipeline as pp

    def explode(request, db):
        raise pp.PolicyEngineError("boom")

    monkeypatch.setattr(pp, "evaluate_request", explode)
    response = client.get("/protected/data", headers=_auth(user_token))
    assert response.status_code == 500
    assert response.json()["error"] == "INTERNAL_SECURITY_ERROR"


def test_dlp_engine_failure_returns_500(client, db_session, user_token, backend_url, monkeypatch):
    _seed_default_policies(db_session)
    import app.services.dlp_service as dlp_service

    monkeypatch.setattr(dlp_service, "engine_path", lambda: "/nonexistent/binary")
    response = client.get("/protected/data", headers=_auth(user_token))
    assert response.status_code == 500
    assert response.json()["error"] == "INTERNAL_SECURITY_ERROR"


def test_backend_unreachable_returns_502(client, db_session, user_token, monkeypatch):
    _seed_default_policies(db_session)
    monkeypatch.setenv("BACKEND_URL", "http://127.0.0.1:1/")
    reset_settings_cache()
    try:
        response = client.get("/protected/data", headers=_auth(user_token))
        assert response.status_code == 502
        assert response.json() == {
            "error": "BACKEND_UNAVAILABLE",
            "message": "Backend did not respond",
        }
        from app.models import AuditEvent

        request_id = response.headers["X-Request-ID"]
        event = (
            db_session.query(AuditEvent)
            .filter(
                AuditEvent.request_id == request_id,
                AuditEvent.reason == "BACKEND_UNAVAILABLE",
            )
            .first()
        )
        assert event is not None
    finally:
        reset_settings_cache()


def test_redis_down_returns_503(client, db_session, user_token, backend_url, monkeypatch):
    from redis.exceptions import ConnectionError as RedisConnectionError

    import app.services.rate_limit_service as rls

    class Broken:
        def pipeline(self, *a, **k):
            raise RedisConnectionError("simulated redis outage")

    monkeypatch.setattr(rls, "create_redis_client", lambda: Broken())
    response = client.get("/protected/data", headers=_auth(user_token))
    assert response.status_code == 503
    assert response.json()["error"] == "INTERNAL_SECURITY_ERROR"


# --------------------------------------------------------------------------- #
# §6 pipeline order proof (R1): dummy stage hooks, exact sequence
# --------------------------------------------------------------------------- #


def _stub_forward(monkeypatch, status_code: int = 200):
    """Dummy forward hook for the stage-order unit tests (R1): no network.

    Replaces gateway_service._forward with a canned Response so the §6 order
    under test is the stage sequencing, not httpx.
    """
    from fastapi.responses import JSONResponse

    import app.services.gateway_service as gw

    async def dummy_forward(request, db):
        return JSONResponse(status_code=status_code, content={"forwarded": True})

    monkeypatch.setattr(gw, "_forward", dummy_forward)


def test_pipeline_stage_order_exact_sequence(db_session, redis_client, monkeypatch):
    """R1: with dummy stage hooks, the §6 sequence is recorded exactly.

    Drives `handle_protected` directly with a stub request + dummy forward
    hook so the order of stage invocations — not FastAPI or httpx — is what
    is under test.
    """
    _stub_forward(monkeypatch)
    from types import SimpleNamespace

    from app.core.security import hash_password
    from app.models import USER, User
    from app.services.gateway_service import PipelineStage, StageRecorder, handle_protected

    user = User(
        username="orderuser",
        email="orderuser@example.com",
        password_hash=hash_password("strong-password"),
        role=USER,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()

    from app.db.seed import DEFAULT_POLICIES
    from app.models import Policy

    for spec in DEFAULT_POLICIES:
        db_session.add(Policy(**spec))
    db_session.commit()

    recorder = StageRecorder()
    request = SimpleNamespace(
        state=SimpleNamespace(
            request_id="order-test-0001",
            method="GET",
            path="/protected/data",
            source_ip="testclient",
            user=user,
            user_role=user.role,
        ),
        url=SimpleNamespace(path="/protected/data", query=""),
        headers={},
        method="GET",
        client=None,
    )

    async def _run():
        return await handle_protected(
            request, current_user=user, db=db_session, stages=recorder
        )

    import asyncio

    response = asyncio.run(_run())
    assert response.status_code == 200

    expected = [
        PipelineStage.AUTHENTICATION,
        PipelineStage.AUTHORIZATION,
        PipelineStage.RATE_LIMITING,
        PipelineStage.DLP,
        PipelineStage.RISK,
        PipelineStage.POLICY,
        PipelineStage.FORWARD,
        PipelineStage.AUDIT,
    ]
    assert recorder.names == expected, recorder.names


def test_blocked_flow_stage_order_stops_before_forward(db_session, redis_client, monkeypatch):
    """BLOCK short-circuits: FORWARD never appears in the recorded sequence."""
    _stub_forward(monkeypatch)
    from types import SimpleNamespace

    from app.core.security import hash_password
    from app.models import USER, User
    from app.services.gateway_service import PipelineStage, StageRecorder, handle_protected

    from app.db.seed import DEFAULT_POLICIES
    from app.models import Policy

    for spec in DEFAULT_POLICIES:
        db_session.add(Policy(**spec))
    db_session.commit()

    user = User(
        username="orderblock",
        email="orderblock@example.com",
        password_hash=hash_password("strong-password"),
        role=USER,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()

    recorder = StageRecorder()

    block_body = b'{"aadhaar": "aadhaar 234123412345", "api_key": "api_key=supersecrettoken123"}'

    async def _body():
        return block_body

    request = SimpleNamespace(
        state=SimpleNamespace(
            request_id="order-block-0001",
            method="POST",
            path="/protected/upload",
            source_ip="testclient",
            user=user,
            user_role=user.role,
        ),
        url=SimpleNamespace(path="/protected/upload", query=""),
        headers={},
        method="POST",
        client=None,
        body=_body,
    )

    async def _run():
        return await handle_protected(
            request, current_user=user, db=db_session, stages=recorder
        )

    import asyncio

    response = asyncio.run(_run())
    assert response.status_code == 403
    assert PipelineStage.FORWARD not in recorder.names
    assert PipelineStage.AUDIT in recorder.names
    assert recorder.names.index(PipelineStage.DLP) < recorder.names.index(
        PipelineStage.POLICY
    )
