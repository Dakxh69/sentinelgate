"""audit_events table (spec section 21).

`detected_categories` is JSONB on PostgreSQL and JSON on SQLite (tests use the
sqlite variant; production always runs PostgreSQL).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, BigInteger, Boolean, DateTime, Float, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base

# JSONB on PostgreSQL, plain JSON on SQLite (test fallback).
JSONVariant = JSONB().with_variant(JSON(), "sqlite")
# BIGSERIAL on PostgreSQL; plain INTEGER on SQLite (test fallback).
BigIntPK = BigInteger().with_variant(Integer(), "sqlite")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, server_default=func.now()
    )
    user_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    path: Mapped[str | None] = mapped_column(String(255), nullable=True)
    decision: Mapped[str | None] = mapped_column(String(16), nullable=True)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    detected_categories: Mapped[list[Any] | None] = mapped_column(
        JSONVariant, nullable=True
    )
    reason: Mapped[str | None] = mapped_column(String(128), nullable=True)
    response_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    forwarded: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=func.true())
    forwarded: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=func.true())
