"""initial schema: users, policies, audit_events

Revision ID: 0001_initial
Revises:
Create Date: 2026-10-06

Spec section 21 — exact columns. `detected_categories` is JSONB on
PostgreSQL (JSON variant on SQLite for tests).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from app.models.audit import JSONVariant

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(), server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("username", name=op.f("uq_users_username")),
        sa.UniqueConstraint("email", name=op.f("uq_users_email")),
    )

    op.create_table(
        "policies",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=True),
        sa.Column("path_pattern", sa.String(length=255), nullable=True),
        sa.Column("http_method", sa.String(length=16), nullable=True),
        sa.Column("sensitive_required", sa.Boolean(), nullable=True),
        sa.Column("minimum_risk", sa.Float(), nullable=True),
        sa.Column("action", sa.String(length=16), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(), server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_policies")),
    )

    op.create_table(
        "audit_events",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("request_id", sa.String(length=64), nullable=False),
        sa.Column(
            "timestamp", sa.DateTime(), server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("user_id", sa.BigInteger(), nullable=True),
        sa.Column("role", sa.String(length=32), nullable=True),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.Column("method", sa.String(length=16), nullable=True),
        sa.Column("path", sa.String(length=255), nullable=True),
        sa.Column("decision", sa.String(length=16), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("detected_categories", JSONVariant, nullable=True),
        sa.Column("reason", sa.String(length=128), nullable=True),
        sa.Column("response_status", sa.Integer(), nullable=True),
        sa.Column("forwarded", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_events")),
    )
    op.create_index(
        op.f("ix_audit_events_request_id"), "audit_events", ["request_id"]
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_audit_events_request_id"), table_name="audit_events")
    op.drop_table("audit_events")
    op.drop_table("policies")
    op.drop_column("audit_events", "forwarded")
    op.drop_table("users")
