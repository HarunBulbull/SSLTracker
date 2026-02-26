"""Veritabanı CRUD işlemleri."""
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Domain
from app.schemas import DomainCreate, DomainUpdate
from app.ssl_checker import SSLInfo, get_ssl_info


async def get_domains(db: AsyncSession, include_expired: bool = True):
    """Tüm domainleri getirir."""
    q = select(Domain).order_by(Domain.domain)
    result = await db.execute(q)
    domains = result.scalars().all()
    if not include_expired:
        domains = [d for d in domains if d.days_until_expiry is None or d.days_until_expiry >= 0]
    return domains


async def get_domain_by_id(db: AsyncSession, domain_id: int) -> Domain | None:
    """ID ile domain getirir."""
    result = await db.execute(select(Domain).where(Domain.id == domain_id))
    return result.scalar_one_or_none()


async def get_domain_by_name(db: AsyncSession, domain: str) -> Domain | None:
    """Domain adı ile getirir."""
    result = await db.execute(select(Domain).where(Domain.domain == domain.strip().lower()))
    return result.scalar_one_or_none()


async def create_domain(db: AsyncSession, data: DomainCreate) -> Domain:
    """Yeni domain ekler ve ilk SSL kontrolünü yapar."""
    domain = Domain(domain=data.domain.strip().lower(), notes=data.notes)
    db.add(domain)
    await db.flush()
    info = get_ssl_info(domain.domain)
    _apply_ssl_info(domain, info)
    await db.flush()
    await db.refresh(domain)
    return domain


def _apply_ssl_info(domain: Domain, info: SSLInfo) -> None:
    domain.last_checked_at = datetime.now(timezone.utc)
    domain.expires_at = info.expires_at
    domain.issuer = info.issuer
    domain.days_until_expiry = info.days_until_expiry
    domain.ssl_valid = info.valid
    domain.last_error = info.error


async def update_domain(db: AsyncSession, domain: Domain, data: DomainUpdate) -> Domain:
    """Domain günceller."""
    if data.notes is not None:
        domain.notes = data.notes
    await db.flush()
    await db.refresh(domain)
    return domain


async def delete_domain(db: AsyncSession, domain: Domain) -> None:
    """Domain siler."""
    await db.delete(domain)
    await db.flush()


async def refresh_ssl(db: AsyncSession, domain: Domain) -> Domain:
    """Domain için SSL bilgisini yeniler."""
    info = get_ssl_info(domain.domain)
    _apply_ssl_info(domain, info)
    await db.flush()
    await db.refresh(domain)
    return domain


async def refresh_all_ssl(db: AsyncSession) -> int:
    """Tüm domainlerin SSL bilgisini yeniler."""
    domains = await get_domains(db)
    for d in domains:
        info = get_ssl_info(d.domain)
        _apply_ssl_info(d, info)
    await db.flush()
    return len(domains)
