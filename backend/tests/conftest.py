"""Shared pytest fixtures.

Configuration strategy (specs/README.md environment notes):
  - If TEST_DATABASE_URL / TEST_REDIS_URL are set, tests run against those
    real services (preferred on this machine: local PostgreSQL 16.4 + Redis
    7.4.1 from scripts/dev_services.sh).
  - Otherwise the suite falls back to SQLite (JSON-variant for audit_events)
    and fakeredis so it stays runnable offline.
The chosen mode is printed once per session.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "sqlite+pysqlite://")
TEST_REDIS_URL = os.environ.get("TEST_REDIS_URL", "")

IS_REAL_DB = TEST_DATABASE_URL.startswith("postgresql")
IS_REAL_REDIS = TEST_REDIS_URL.startswith("redis")


@pytest.fixture(scope="session", autouse=True)
def _configure_environment():
    """Point app settings at the test services before anything imports them."""
    os.environ["DATABASE_URL"] = TEST_DATABASE_URL
    os.environ["JWT_SECRET"] = os.environ.get("JWT_SECRET", "test-secret-not-a-real-secret-32bytes!")
    os.environ["REDIS_URL"] = TEST_REDIS_URL or "redis://fake-redis-unavailable:6379/0"
    from app.core.config import reset_settings_cache

    reset_settings_cache()
    mode = (
        f"real postgresql ({TEST_DATABASE_URL.rsplit('/', 1)[-1]})"
        if IS_REAL_DB
        else "sqlite fallback"
    )
    print(f"\n[conftest] db mode: {mode} | redis mode: "
          f"{'real redis' if IS_REAL_REDIS else 'fakeredis fallback'}")
    yield
    reset_settings_cache()


@pytest.fixture()
def db_session():
    """Yield a session on a freshly created schema; drop afterwards."""
    from app.core.database import engine
    from app.models import Base

    Base.metadata.create_all(engine)
    SessionLocal = __import__(
        "app.core.database", fromlist=["SessionLocal"]
    ).SessionLocal
    session = SessionLocal()
    try:
        yield session
        session.rollback()
    finally:
        session.close()
        Base.metadata.drop_all(engine)


@pytest.fixture()
def redis_client():
    """Yield a Redis client; fakeredis fallback when no real service is set."""
    if IS_REAL_REDIS:
        from app.core.redis_client import create_redis_client

        client = create_redis_client()
    else:
        import fakeredis

        client = fakeredis.FakeRedis(decode_responses=True)
    try:
        # Route every app-level Redis use (health, rate limiter) through the
        # same client the tests flush afterwards — shared-state semantics.
        import app.core.redis_client as rc

        rc._client_override = client
        yield client
    finally:
        try:
            client.flushdb()
        except Exception:  # noqa: BLE001 - cleanup must never fail the suite
            pass
        import app.core.redis_client as rc

        rc._client_override = None


@pytest.fixture()
def client(db_session, redis_client):
    """TestClient with dependency overrides for DB + Redis."""
    from fastapi.testclient import TestClient

    import app.main as app_module
    from app.core.database import get_db

    def _override_db():
        yield db_session

    app_module.app.dependency_overrides[get_db] = _override_db
    app_module._redis_override = redis_client  # health check uses this when set
    with TestClient(app_module.app) as test_client:
        yield test_client
    app_module.app.dependency_overrides.clear()
    app_module._redis_override = None


@pytest.fixture()
def backend_url(monkeypatch):
    """Run the demo backend on a real local port and aim BACKEND_URL at it.

    Lets integration tests exercise the production httpx forwarding path
    (real uvicorn on 127.0.0.1, no Docker). See test_gateway.py for usage.
    """
    import socket
    import threading
    import time

    import uvicorn

    from app.core.config import reset_settings_cache
    from app.internal.main import internal_app

    def _free_port() -> int:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]

    port = _free_port()
    config = uvicorn.Config(internal_app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(50):
        if server.started:
            break
        time.sleep(0.1)
    if not server.started:
        pytest.fail("internal backend server did not start")

    base = f"http://127.0.0.1:{port}"
    monkeypatch.setenv("BACKEND_URL", base)
    reset_settings_cache()
    yield base
    server.should_exit = True
    thread.join(timeout=5)
    reset_settings_cache()
