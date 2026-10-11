"""Safe user representation schema."""

from __future__ import annotations

from pydantic import BaseModel


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    role: str
    created_at: str
    is_active: bool
