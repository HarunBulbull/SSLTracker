"""Uygulama yapılandırması."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("WEBTRACKER_DATA", str(BASE_DIR / "data")))
DB_PATH = DATA_DIR / "webtracker.db"
# Sertifikalar proje klasöründe (webTracker/certs)
CERTS_DIR = BASE_DIR / "certs"
CERTBOT_USER_DIR = Path(os.environ.get("CERTBOT_USER_DIR", str(CERTS_DIR)))
CERTBOT_USER_WORK = CERTBOT_USER_DIR / "work"
CERTBOT_USER_LOGS = CERTBOT_USER_DIR / "logs"
# Sistem certbot (okuma; varsa indirme için)
CERTBOT_DIR = Path(os.environ.get("CERTBOT_DIR", "/etc/letsencrypt"))
CERTBOT_LIVE = CERTBOT_DIR / "live"
# Sabit: Yenile ile certbot bu e-posta ve webroot kullanır
CERTBOT_EMAIL = os.environ.get("CERTBOT_EMAIL", "info@harunbulbul.com")
CERTBOT_WEBROOT = os.environ.get("CERTBOT_WEBROOT", "/var/www/html")
SSL_CHECK_INTERVAL_MINUTES = int(os.environ.get("SSL_CHECK_INTERVAL", "60"))
WARN_DAYS_BEFORE_EXPIRY = int(os.environ.get("WARN_DAYS", "30"))
CRITICAL_DAYS_BEFORE_EXPIRY = int(os.environ.get("CRITICAL_DAYS", "7"))
APP_TIMEZONE = os.environ.get("APP_TIMEZONE", "Europe/Istanbul")


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


# SMTP (cPanel) ayarları
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_USE_TLS = _env_bool("SMTP_USE_TLS", True)
SMTP_USE_SSL = _env_bool("SMTP_USE_SSL", False)
SMTP_FROM_EMAIL = os.environ.get("SMTP_FROM_EMAIL", SMTP_USERNAME or "noreply@localhost")
SMTP_TO_EMAILS = [item.strip() for item in os.environ.get("SMTP_TO_EMAILS", "").split(",") if item.strip()]

# SSL bitiş uyarı cron ayarları
SSL_ALERT_THRESHOLD_DAYS = int(os.environ.get("SSL_ALERT_THRESHOLD_DAYS", "2"))
SSL_ALERT_CRON_HOUR = int(os.environ.get("SSL_ALERT_CRON_HOUR", "9"))
SSL_ALERT_CRON_MINUTE = int(os.environ.get("SSL_ALERT_CRON_MINUTE", "0"))

DATA_DIR.mkdir(parents=True, exist_ok=True)
CERTBOT_USER_DIR.mkdir(parents=True, exist_ok=True)
CERTBOT_USER_WORK.mkdir(parents=True, exist_ok=True)
CERTBOT_USER_LOGS.mkdir(parents=True, exist_ok=True)
