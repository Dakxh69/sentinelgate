"""add audit_events.forwarded column

Revision ID: 0002_audit_forwarded
Revises: 0001_initial
Create Date: 2026-10-12

Adds a `forwarded` Boolean to `audit_events` so an ADMIN reading the audit log
can tell whether an ALLOW actually reached the backend (P0 R1).

Old rows: true (assume forwarded; every ALLOW before this migration was
forwarded, and the backward-compatible code never set the field).

Downgrade: drop the column (loses the answer, not the rows).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_audit_forwarded"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "audit_events",
        sa.Column(
            "forwarded",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
    )


def downgrade() -> None:
    op.drop_column("audit_events", "forwarded")
