"""Rate limit tests (Day 3 R5, spec sections 12/34/35.4)."""

from __future__ import annotations

import pytest

REGISTER_BODY = {
    "username": "rluser",
    "email": "rluser@example.com",
    "password": "strong-password",
}

FOUR_TWENTY_NINE_BODY = {
    "error": "RATE_LIMIT_EXCEEDED",
    "message": "Too many requests",
}


@pytest.fixture()
def small_limit(monkeypatch):
    """Configure a tiny window so boundary tests are fast."""
    from app.core.config import get_settings, reset_settings_cache
    import os

    monkeypatch.setenv("RATE_LIMIT_REQUESTS", "3")
    monkeypatch.setenv("RATE_LIMIT_WINDOW_SECONDS", "60")
    reset_settings_cache()
    yield get_settings()
    monkeypatch.delenv("RATE_LIMIT_REQUESTS", raising=False)
    monkeypatch.delenv("RATE_LIMIT_WINDOW_SECONDS", raising=False)
    reset_settings_cache()


@pytest.fixture()
def user_auth(client, small_limit, backend_url):
    response = client.post("/auth/register", json=REGISTER_BODY)
    assert response.status_code == 201, response.text
    login_response = client.post(
        "/auth/login",
        json={"email": REGISTER_BODY["email"], "password": REGISTER_BODY["password"]},
    )
    assert login_response.status_code == 200, login_response.text
    return login_response.json()["access_token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ------------------------------------------- boundary semantics (spec 34)


def test_requests_up_to_limit_allowed_then_429(client, user_auth):
    codes = [
        client.get("/protected/data", headers=_auth(user_auth)).status_code
        for _ in range(5)
    ]
    # count <= limit allowed (3), count > limit → 429 (spec 34 documented semantics)
    assert codes == [200, 200, 200, 429, 429]


def test_429_body_matches_spec(client, user_auth):
    for _ in range(4):
        response = client.get("/protected/data", headers=_auth(user_auth))
    assert response.status_code == 429
    assert response.json() == FOUR_TWENTY_NINE_BODY


def test_429_carries_request_id(client, user_auth):
    for _ in range(4):
        response = client.get("/protected/data", headers=_auth(user_auth))
    assert response.headers.get("X-Request-ID")


# ------------------------------------------- shared, independent counters


def test_users_have_independent_counters(client, monkeypatch, backend_url):
    """Limit 10: user0 exhausts their counter, user1 is unaffected."""
    from app.core.config import get_settings, reset_settings_cache

    monkeypatch.setenv("RATE_LIMIT_REQUESTS", "10")
    reset_settings_cache()
    try:
        tokens = []
        for i in range(2):
            body = dict(
                REGISTER_BODY, username=f"user{i}", email=f"user{i}@example.com"
            )
            assert client.post("/auth/register", json=body).status_code == 201
            login_response = client.post(
                "/auth/login",
                json={"email": body["email"], "password": body["password"]},
            )
            assert login_response.status_code == 200
            tokens.append(login_response.json()["access_token"])

        # User 0 exhausts their window; user 1 is unaffected (shared Redis,
        # per-user keys — not in-process memory, spec 12).
        codes_u0 = [
            client.get("/protected/data", headers=_auth(tokens[0])).status_code
            for _ in range(11)
        ]
        assert codes_u0[-1] == 429
        assert client.get("/protected/data", headers=_auth(tokens[1])).status_code == 200
    finally:
        monkeypatch.delenv("RATE_LIMIT_REQUESTS", raising=False)
        reset_settings_cache()


# ------------------------------------------- window rollover (spec 34)


def test_window_rollover_resets_counter(client, user_auth, monkeypatch):
    import app.services.rate_limit_service as rls

    for _ in range(4):
        client.get("/protected/data", headers=_auth(user_auth))
    assert client.get("/protected/data", headers=_auth(user_auth)).status_code == 429

    # Jump the clock past the window boundary: counters restart.
    real_window = rls._window
    monkeypatch.setattr(
        rls, "_window", lambda now_epoch=None: real_window() + 1
    )
    assert client.get("/protected/data", headers=_auth(user_auth)).status_code == 200


# ------------------------------------------- no bypass (spec 35.4)


def test_repeated_requests_cannot_bypass_limit(client, user_auth):
    codes = {
        client.get("/protected/data", headers=_auth(user_auth)).status_code
        for _ in range(20)
    }
    assert 429 in codes  # hammering never yields unlimited access


# ------------------------------------------- Redis failure → fail closed


def test_redis_down_returns_503_never_allow(client, user_auth, monkeypatch):
    from redis.exceptions import ConnectionError as RedisConnectionError

    import app.services.rate_limit_service as rls

    class Broken:
        def pipeline(self, *a, **k):
            raise RedisConnectionError("simulated redis outage")

    monkeypatch.setattr(rls, "create_redis_client", lambda: Broken())
    response = client.get("/protected/data", headers=_auth(user_auth))
    assert response.status_code == 503
    assert response.json() == {
        "error": "INTERNAL_SECURITY_ERROR",
        "message": "Rate limiter unavailable",
    }


# ------------------------------------------- auth endpoints are IP-limited (§36)


def test_auth_endpoints_ip_limited(client, small_limit):
    seen = []
    for _ in range(6):
        response = client.post(
            "/auth/login",
            json={"email": "nobody@example.com", "password": "wrong-password"},
        )
        seen.append(response.status_code)
    # Same 401 body for attempts within the window; 429 once the IP window fills.
    assert all(code in (401, 429) for code in seen)
    assert seen[-1] == 429
