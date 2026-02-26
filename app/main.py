"""FastAPI uygulaması."""
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.config import DATA_DIR, SSL_CHECK_INTERVAL_MINUTES
from app.database import init_db, AsyncSessionLocal
from app import models  # noqa: F401 - register models before init_db
from app.crud import refresh_all_ssl
from app.routers import domains

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


async def scheduled_ssl_refresh():
    """Arka planda tüm domainlerin SSL bilgisini yeniler."""
    async with AsyncSessionLocal() as db:
        await refresh_all_ssl(db)
        await db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Uygulama başlangıç/bitiş."""
    await init_db()
    app.state.templates = templates
    scheduler = AsyncIOScheduler()
    scheduler.add_job(scheduled_ssl_refresh, "interval", minutes=SSL_CHECK_INTERVAL_MINUTES)
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
