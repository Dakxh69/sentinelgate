"""policies table (spec section 21)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, Float, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base

# BIGSERIAL on PostgreSQL; plain INTEGER on SQLite (test fallback).
BigIntPK = BigInteger().with_variant(Integer(), "sqlite")


class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    path_pattern: Mapped[str | None] = mapped_column(String(255), nullable=True)
    http_method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    sensitive_required: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    minimum_risk: Mapped[float | None] = mapped_column(Float, nullable=True)
    action: Mapped[str] = mapped_column(String(16), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, server_default=func.now()
    )
