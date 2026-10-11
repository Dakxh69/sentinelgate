"""Audit log response schemas."""

from __future__ import annotations

from pydantic import BaseModel


class AuditEventOut(BaseModel):
    id: int
    request_id: str
    timestamp: str | None = None
    user_id: int | None = None
    role: str | None = None
    source_ip: str | None = None
    method: str | None = None
    path: str | None = None
    decision: str | None = None
    risk_score: float | None = None
    detected_categories: list[str] | None = None
    reason: str | None = None
    response_status: int | None = None
    forwarded: bool = True


class AuditPage(BaseModel):
    items: list[AuditEventOut]
    total: int
    limit: int
    offset: int
