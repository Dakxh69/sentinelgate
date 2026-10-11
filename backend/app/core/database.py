"""SQLAlchemy database engine and session configuration."""

from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import get_settings

settings = get_settings()


def _build_engine():
    """Create the app engine; SQLite in-memory shares one connection.

    A plain in-memory SQLite gives every pooled connection its own empty
    database, so schema created in one session is invisible to another.
    StaticPool keeps a single shared connection — used only for the SQLite
    test fallback (real deployments run PostgreSQL).
    """
    url = settings.sync_database_url()
    if url.startswith("sqlite") and (":memory:" in url or url.endswith("://")):
        return create_engine(
            url,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
    return create_engine(url, pool_pre_ping=True)


engine = _build_engine()

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Iterator[Session]:
    """FastAPI dependency yielding a DB session (used by routes and seed)."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
