"""SSL sertifika süresi kontrolü."""
import ssl
import socket
from datetime import datetime, timezone
from typing import NamedTuple


class SSLInfo(NamedTuple):
    expires_at: datetime | None
    issuer: str | None
    days_until_expiry: int | None
    valid: bool
    error: str | None


def get_ssl_info(domain: str, port: int = 443, timeout: float = 10.0) -> SSLInfo:
    """
    Domain için SSL sertifika bilgisini alır.
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return SSLInfo(None, None, None, False, "Sertifika alınamadı")
                # 'notAfter' format: 'Feb 26 12:00:00 2026 GMT'
                not_after = cert.get("notAfter")
                if not not_after:
                    return SSLInfo(None, None, None, False, "notAfter yok")
                expires_at = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                delta = expires_at - now
                days = delta.days
                issuer = ""
                if "issuer" in cert:
                    iss = cert["issuer"]
                    if isinstance(iss, tuple):
                        for item in iss:
                            if isinstance(item, tuple):
                                for (k, v) in item:
                                    if k == "organizationName":
                                        issuer = v
                                        break
                    if not issuer and isinstance(iss, list):
                        for item in iss:
                            if isinstance(item, dict) and "organizationName" in item:
                                issuer = item["organizationName"]
                                break
                return SSLInfo(expires_at=expires_at, issuer=issuer or None, days_until_expiry=days, valid=True, error=None)
    except ssl.SSLCertVerificationError as e:
        return SSLInfo(None, None, None, False, str(e))
    except socket.gaierror as e:
        return SSLInfo(None, None, None, False, f"DNS/bağlantı: {e}")
    except (socket.timeout, TimeoutError) as e:
        return SSLInfo(None, None, None, False, f"Zaman aşımı: {e}")
    except Exception as e:
        return SSLInfo(None, None, None, False, str(e))
