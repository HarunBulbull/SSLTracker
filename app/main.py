"""FastAPI uygulaması."""
from contextlib import asynccontextmanager
from pathlib import Path
import logging

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.config import (
    APP_TIMEZONE,
    DATA_DIR,
    SSL_ALERT_CRON_HOUR,
    SSL_ALERT_CRON_MINUTE,
    SSL_ALERT_THRESHOLD_DAYS,
    SSL_CHECK_INTERVAL_MINUTES,
)
from app.database import init_db, AsyncSessionLocal
from app import models  # noqa: F401 - register models before init_db
from app.crud import get_domains_expiring_within_days, refresh_all_ssl
from app.mailer import send_ssl_alert_email
from app.routers import domains

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
logger = logging.getLogger(__name__)


async def scheduled_ssl_refresh():
    """Arka planda tüm domainlerin SSL bilgisini yeniler."""
    async with AsyncSessionLocal() as db:
        await refresh_all_ssl(db)
        await db.commit()


async def scheduled_ssl_expiry_alert():
    """Her sabah kritik SSL sürelerini e-posta ile bildirir."""
    async with AsyncSessionLocal() as db:
        await refresh_all_ssl(db)
        expiring_domains = await get_domains_expiring_within_days(db, SSL_ALERT_THRESHOLD_DAYS)
        sent = await send_ssl_alert_email(expiring_domains)
        await db.commit()
        if sent:
            logger.info("SSL bitis uyarisi gonderildi. Adet: %s", len(expiring_domains))


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Uygulama başlangıç/bitiş."""
    await init_db()
    app.state.templates = templates
    scheduler = AsyncIOScheduler(timezone=APP_TIMEZONE)
    scheduler.add_job(scheduled_ssl_refresh, "interval", minutes=SSL_CHECK_INTERVAL_MINUTES)
    scheduler.add_job(
        scheduled_ssl_expiry_alert,
        "cron",
        hour=SSL_ALERT_CRON_HOUR,
        minute=SSL_ALERT_CRON_MINUTE,
    )
    scheduler.start()
    yield
    scheduler.shutdown(wait=False)


app = FastAPI(
    title="webTracker",
    description="SSL domain takip ve Certbot sertifika yönetimi",
    lifespan=lifespan,
)
app.include_router(domains.router)


@app.get("/health")
async def health():
    return {"status": "ok"}


def get_templates(request: Request):
    return request.app.state.templates
