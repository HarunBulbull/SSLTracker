"""SMTP ile SSL bitiş uyarı e-postaları."""
import asyncio
import logging
import smtplib
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Iterable

from app.config import (
    SMTP_FROM_EMAIL,
    SMTP_HOST,
    SMTP_PASSWORD,
    SMTP_PORT,
    SMTP_TO_EMAILS,
    SMTP_USERNAME,
    SMTP_USE_SSL,
    SMTP_USE_TLS,
)

logger = logging.getLogger(__name__)


def _build_ssl_alert_email(domains: Iterable) -> EmailMessage:
    domains = list(domains)
    msg = EmailMessage()
    msg["Subject"] = f"[SSLTracker] Acil SSL uyarisi ({len(domains)} domain)"
    msg["From"] = SMTP_FROM_EMAIL
    msg["To"] = ", ".join(SMTP_TO_EMAILS)

    lines = [
        "Asagidaki domainlerin SSL suresi 2 gunden az kalmistir:",
        "",
    ]
    for d in domains:
        lines.append(f"- {d.domain}: {d.days_until_expiry} gun kaldi (bitis: {d.expires_at})")
    lines.append("")
    lines.append("Bu e-posta SSLTracker otomatik cron gorevi tarafindan gonderildi.")
    msg.set_content("\n".join(lines))
    return msg


def _send_email_sync(message: EmailMessage) -> None:
    if SMTP_USE_SSL:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=30) as server:
            if SMTP_USERNAME:
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(message)
        return

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
        if SMTP_USE_TLS:
            server.starttls()
        if SMTP_USERNAME:
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(message)


async def send_ssl_alert_email(domains: Iterable) -> bool:
    """SMTP ayarlari varsa SSL suresi kritik domainleri e-posta ile gonderir."""
    domains = list(domains)
    if not domains:
        return False
    if not SMTP_HOST or not SMTP_TO_EMAILS:
        logger.warning("SMTP ayarlari eksik: SMTP_HOST veya SMTP_TO_EMAILS tanimli degil.")
        return False

    message = _build_ssl_alert_email(domains)
    await asyncio.to_thread(_send_email_sync, message)
    return True


def _build_test_email() -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = "[SSLTracker] SMTP test e-postasi"
    msg["From"] = SMTP_FROM_EMAIL
    msg["To"] = ", ".join(SMTP_TO_EMAILS)
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    msg.set_content(
        "\n".join(
            [
                "Bu bir SSLTracker SMTP test e-postasidir.",
                f"Gonderim zamani: {now_utc}",
                "",
                "Bu mesaj elle tetiklenen test butonundan gonderildi.",
            ]
        )
    )
    return msg


async def send_test_email() -> bool:
    """SMTP ayarlari uygunsa test e-postasi gonderir."""
    if not SMTP_HOST or not SMTP_TO_EMAILS:
        logger.warning("SMTP ayarlari eksik: SMTP_HOST veya SMTP_TO_EMAILS tanimli degil.")
        return False
    message = _build_test_email()
    await asyncio.to_thread(_send_email_sync, message)
    return True
