"""Health endpoint tests (Day 1 R8, spec section 31)."""

from __future__ import annotations


def test_health_returns_ok_when_services_up(client):
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["checks"] == {"postgres": "ok", "redis": "ok"}


def test_health_returns_503_naming_failing_service(client, monkeypatch):
    import app.main as app_module

    def broken_postgres():
        raise RuntimeError("simulated postgres outage")

    monkeypatch.setattr(app_module, "check_postgres", broken_postgres)
    response = client.get("/health")
    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "degraded"
    assert body["checks"]["postgres"] == "error"
    assert body["checks"]["redis"] == "ok"
    # Spec 31: a degraded health check must name the failing service.
    assert "postgres" in body["checks"]


def test_health_redis_failure_names_redis(client, monkeypatch):
    import app.main as app_module

    def broken_redis():
        raise ConnectionError("simulated redis outage")

    monkeypatch.setattr(app_module, "check_redis", broken_redis)
    response = client.get("/health")
    assert response.status_code == 503
    body = response.json()
    assert body["checks"]["redis"] == "error"
    assert body["checks"]["postgres"] == "ok"


def test_health_never_raises(client, monkeypatch):
    import app.main as app_module

    def explodes_postgres():
        raise RuntimeError("boom")

    def explodes_redis():
        raise RuntimeError("boom")

    monkeypatch.setattr(app_module, "check_postgres", explodes_postgres)
    monkeypatch.setattr(app_module, "check_redis", explodes_redis)
    response = client.get("/health")  # must not raise
    assert response.status_code == 503
    assert response.json()["status"] == "degraded"
