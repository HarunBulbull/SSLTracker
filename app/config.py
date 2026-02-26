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

DATA_DIR.mkdir(parents=True, exist_ok=True)
CERTBOT_USER_DIR.mkdir(parents=True, exist_ok=True)
CERTBOT_USER_WORK.mkdir(parents=True, exist_ok=True)
CERTBOT_USER_LOGS.mkdir(parents=True, exist_ok=True)
