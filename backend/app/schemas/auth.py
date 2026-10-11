"""Pydantic schemas for authentication and registration endpoints."""

from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field


class RegisterBody(BaseModel):
    """Registration request payload."""

    username: str = Field(min_length=3, max_length=32)
    email: EmailStr
    password: str = Field(min_length=8)


class LoginBody(BaseModel):
    """Login request payload."""

    email: EmailStr
    password: str


class TokenBody(BaseModel):
    """JWT bearer token response payload."""

    access_token: str
    token_type: str = "bearer"
