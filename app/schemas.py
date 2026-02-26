"""Pydantic şemaları."""
from datetime import datetime
from pydantic import BaseModel, Field


class DomainCreate(BaseModel):
    domain: str = Field(..., min_length=1, max_length=253)
    notes: str | None = None


class DomainUpdate(BaseModel):
    notes: str | None = None


class DomainResponse(BaseModel):
    id: int
    domain: str
    created_at: datetime
    last_checked_at: datetime | None
    expires_at: datetime | None
    issuer: str | None
    days_until_expiry: int | None
    ssl_valid: bool
    last_error: str | None
    cert_path: str | None
    key_path: str | None
    chain_path: str | None
    notes: str | None

    class Config:
        from_attributes = True


class CertPathsResponse(BaseModel):
    cert_path: str
    key_path: str
    chain_path: str
    fullchain_path: str
