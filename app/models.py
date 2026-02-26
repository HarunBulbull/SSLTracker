"""Veritabanı modelleri."""
from datetime import datetime
from sqlalchemy import String, Integer, DateTime, Text, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


class Domain(Base):
    __tablename__ = "domains"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    domain: Mapped[str] = mapped_column(String(253), unique=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    issuer: Mapped[str | None] = mapped_column(String(512), nullable=True)
    days_until_expiry: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ssl_valid: Mapped[bool] = mapped_column(Boolean, default=False)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    cert_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    key_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    chain_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    def status(self) -> str:
        """Durum: ok, warning, critical, expired, unknown."""
        if self.days_until_expiry is None:
            return "unknown"
        if self.days_until_expiry < 0:
            return "expired"
        if self.days_until_expiry <= 7:
            return "critical"
        if self.days_until_expiry <= 30:
            return "warning"
        return "ok"
