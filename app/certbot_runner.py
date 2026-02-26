"""Certbot ile sertifika üretimi."""
import asyncio
import re
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import NamedTuple

from app.config import CERTBOT_LIVE, CERTBOT_USER_DIR, CERTBOT_USER_WORK, CERTBOT_USER_LOGS

# Manuel doğrulama bekleyen işler: job_id -> { proc, temp_dir, domain_id, domain (sanitized), ... }
_pending_dns: dict[str, dict] = {}
_pending_http: dict[str, dict] = {}


class CertbotResult(NamedTuple):
    success: bool
    cert_path: str | None
    key_path: str | None
    chain_path: str | None
    fullchain_path: str | None
    error: str | None


def _sanitize_domain(domain: str) -> str:
    """Certbot dizin adı için güvenli isim (örn. *.example.com -> example.com)."""
    domain = domain.strip().lower()
    if domain.startswith("*."):
        domain = domain[2:]
    return re.sub(r"[^a-z0-9.-]", "", domain)


async def run_certbot(
    domain: str,
    email: str,
    webroot: str | Path | None = None,
    standalone: bool = False,
    dry_run: bool = False,
) -> CertbotResult:
    """
    Certbot ile sertifika alır.
    Linux'ta certbot kurulu ve root/sudo ile çalıştırılabilir olmalı.
    """
    certbot = shutil.which("certbot")
    if not certbot:
        return CertbotResult(False, None, None, None, None, "certbot bulunamadı. Kurulum: apt install certbot")

    sanitized = _sanitize_domain(domain)
    if not sanitized:
        return CertbotResult(False, None, None, None, None, "Geçersiz domain")

    cmd = [
        certbot,
        "certonly",
        "--non-interactive",
        "--agree-tos",
        "--email",
        email,
        "-d",
        domain if domain.startswith("*.") else sanitized,
        # Root olmadan çalışsın: config/work/logs kullanıcı dizinine yazılır
        "--config-dir",
        str(CERTBOT_USER_DIR),
        "--work-dir",
        str(CERTBOT_USER_WORK),
        "--logs-dir",
        str(CERTBOT_USER_LOGS),
    ]
    if dry_run:
        cmd.append("--dry-run")
    if webroot:
        cmd.extend(["--webroot", "-w", str(webroot)])
    elif standalone:
        cmd.append("--standalone")
    else:
        cmd.append("--standalone")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            err = (stderr or stdout or b"").decode("utf-8", errors="replace").strip()
            return CertbotResult(False, None, None, None, None, err or f"Çıkış kodu: {proc.returncode}")

        # Sertifikalar kullanıcı dizinine yazıldı
        live_dir = CERTBOT_USER_DIR / "live" / sanitized
        cert_path = live_dir / "cert.pem"
        key_path = live_dir / "privkey.pem"
        chain_path = live_dir / "chain.pem"
        fullchain_path = live_dir / "fullchain.pem"

        if not cert_path.exists():
            return CertbotResult(False, None, None, None, None, "Sertifika dosyası oluşturulmadı")

        return CertbotResult(
            success=True,
            cert_path=str(cert_path),
            key_path=str(key_path) if key_path.exists() else None,
            chain_path=str(chain_path) if chain_path.exists() else None,
            fullchain_path=str(fullchain_path) if fullchain_path.exists() else None,
            error=None,
        )
    except Exception as e:
        return CertbotResult(False, None, None, None, None, str(e))


def _path_exists(path: Path) -> bool:
    """Dosya var mı kontrol eder; PermissionError/OSError'da False döner."""
    try:
        return path.exists()
    except OSError:
        return False


def get_cert_paths(domain: str) -> CertbotResult:
    """Mevcut certbot sertifika dizinlerini döndürür. Önce kullanıcı dizinine, yoksa sisteme bakar."""
    sanitized = _sanitize_domain(domain)
    # Önce kullanıcı dizini (web'den üretilen), sonra sistem /etc/letsencrypt
    for base in (CERTBOT_USER_DIR / "live", Path(CERTBOT_LIVE)):
        live_dir = base / sanitized
        cert_path = live_dir / "cert.pem"
        if _path_exists(cert_path):
            return CertbotResult(
                success=True,
                cert_path=str(cert_path),
                key_path=str(live_dir / "privkey.pem") if _path_exists(live_dir / "privkey.pem") else None,
                chain_path=str(live_dir / "chain.pem") if _path_exists(live_dir / "chain.pem") else None,
                fullchain_path=str(live_dir / "fullchain.pem") if _path_exists(live_dir / "fullchain.pem") else None,
                error=None,
            )
    return CertbotResult(False, None, None, None, None, "Sertifika dizini bulunamadı")


async def run_certbot_http_manual(domain: str, email: str, domain_id: int) -> tuple[str | None, str | None, str | None, str | None]:
    """
    HTTP-01 (manuel) ile sertifika başlatır. Domain başka sunucuda: doğrulama dosyasını
    o sunucuya yüklemeniz yeterli. Döner: (job_id, file_name, file_content, error).
    """
    certbot = shutil.which("certbot")
    if not certbot:
        return None, None, None, "certbot bulunamadı. Kurulum: apt install certbot"
    sanitized = _sanitize_domain(domain)
    if not sanitized:
        return None, None, None, "Geçersiz domain"

    temp_dir = Path(tempfile.mkdtemp(prefix="certbot_http_"))
    hook_script = temp_dir / "auth_hook.sh"
    hook_script.write_text(
        "#!/bin/bash\n"
        f'echo "$CERTBOT_TOKEN" > "{temp_dir}/token.txt"\n'
        f'echo "$CERTBOT_VALIDATION" > "{temp_dir}/validation.txt"\n'
        f'while [ ! -f "{temp_dir}/done" ]; do sleep 1; done\n'
        "exit 0\n",
        encoding="utf-8",
    )
    hook_script.chmod(0o755)

    env = {**__import__("os").environ, "CERTBOT_HTTP_WAIT_DIR": str(temp_dir)}
    cmd = [
        certbot,
        "certonly",
        "--manual",
        "--preferred-challenges",
        "http",
        "--agree-tos",
        "--email",
        email,
        "-d",
        sanitized,
        "--config-dir",
        str(CERTBOT_USER_DIR),
        "--work-dir",
        str(CERTBOT_USER_WORK),
        "--logs-dir",
        str(CERTBOT_USER_LOGS),
        "--manual-auth-hook",
        str(hook_script),
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        for _ in range(120):
            await asyncio.sleep(0.5)
            token_file = temp_dir / "token.txt"
            val_file = temp_dir / "validation.txt"
            if token_file.exists() and val_file.exists():
                file_name = token_file.read_text(encoding="utf-8").strip()
                file_content = val_file.read_text(encoding="utf-8").strip()
                job_id = str(uuid.uuid4())
                _pending_http[job_id] = {
                    "proc": proc,
                    "temp_dir": temp_dir,
                    "domain_id": domain_id,
                    "domain": sanitized,
                    "file_name": file_name,
                    "file_content": file_content,
                }
                return job_id, file_name, file_content, None
        proc.kill()
        await proc.wait()
        return None, None, None, "Doğrulama dosyası zaman aşımı (60 sn)"
    except Exception as e:
        return None, None, None, str(e)


async def run_certbot_dns_manual(domain: str, email: str, domain_id: int) -> tuple[str | None, str | None, str | None, str | None]:
    """
    DNS-01 (manuel) ile sertifika başlatır. Domain başka sunucuda olduğunda kullanılır.
    Döner: (job_id, txt_name, txt_value, error). Hata varsa job_id None, error dolu.
    """
    certbot = shutil.which("certbot")
    if not certbot:
        return None, None, None, "certbot bulunamadı. Kurulum: apt install certbot"
    sanitized = _sanitize_domain(domain)
    if not sanitized:
        return None, None, None, "Geçersiz domain"

    temp_dir = Path(tempfile.mkdtemp(prefix="certbot_dns_"))
    hook_script = temp_dir / "auth_hook.sh"
    hook_script.write_text(
        "#!/bin/bash\n"
        f'echo "$CERTBOT_VALIDATION" > "{temp_dir}/validation.txt"\n'
        f'echo "$CERTBOT_DOMAIN" > "{temp_dir}/domain.txt"\n'
        f'while [ ! -f "{temp_dir}/done" ]; do sleep 1; done\n'
        "exit 0\n",
        encoding="utf-8",
    )
    hook_script.chmod(0o755)

    env = {**__import__("os").environ, "CERTBOT_DNS_WAIT_DIR": str(temp_dir)}
    cmd = [
        certbot,
        "certonly",
        "--manual",
        "--preferred-challenges",
        "dns",
        "--agree-tos",
        "--email",
        email,
        "-d",
        sanitized,
        "--config-dir",
        str(CERTBOT_USER_DIR),
        "--work-dir",
        str(CERTBOT_USER_WORK),
        "--logs-dir",
        str(CERTBOT_USER_LOGS),
        "--manual-auth-hook",
        str(hook_script),
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        for _ in range(120):
            await asyncio.sleep(0.5)
            val_file = temp_dir / "validation.txt"
            if val_file.exists():
                txt_value = val_file.read_text(encoding="utf-8").strip()
                domain_file = temp_dir / "domain.txt"
                txt_name = f"_acme-challenge.{domain_file.read_text(encoding='utf-8').strip()}" if domain_file.exists() else f"_acme-challenge.{sanitized}"
                job_id = str(uuid.uuid4())
                _pending_dns[job_id] = {
                    "proc": proc,
                    "temp_dir": temp_dir,
                    "domain_id": domain_id,
                    "domain": sanitized,
                    "txt_name": txt_name,
                    "txt_value": txt_value,
                }
                return job_id, txt_name, txt_value, None
        proc.kill()
        await proc.wait()
        return None, None, None, "TXT dosyası zaman aşımı (60 sn)"
    except Exception as e:
        return None, None, None, str(e)


async def continue_certbot_http(job_id: str) -> CertbotResult:
    """HTTP-01 işinde kullanıcı dosyayı yükledikten sonra certbot'u devam ettirir."""
    if job_id not in _pending_http:
        return CertbotResult(False, None, None, None, None, "Geçersiz veya süresi dolmuş iş")
    entry = _pending_http[job_id]
    proc = entry["proc"]
    temp_dir = entry["temp_dir"]
    try:
        (temp_dir / "done").write_text("1", encoding="utf-8")
        try:
            await asyncio.wait_for(proc.wait(), timeout=120.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return CertbotResult(False, None, None, None, None, "Certbot zaman aşımı")
        if proc.returncode != 0:
            err = (await proc.stderr.read()).decode("utf-8", errors="replace").strip() if proc.stderr else ""
            return CertbotResult(False, None, None, None, None, err or f"Çıkış kodu: {proc.returncode}")
        sanitized = entry["domain"]
        live_dir = CERTBOT_USER_DIR / "live" / sanitized
        cert_path = live_dir / "cert.pem"
        if not cert_path.exists():
            return CertbotResult(False, None, None, None, None, "Sertifika dosyası oluşturulmadı")
        return CertbotResult(
            success=True,
            cert_path=str(cert_path),
            key_path=str(live_dir / "privkey.pem") if (live_dir / "privkey.pem").exists() else None,
            chain_path=str(live_dir / "chain.pem") if (live_dir / "chain.pem").exists() else None,
            fullchain_path=str(live_dir / "fullchain.pem") if (live_dir / "fullchain.pem").exists() else None,
            error=None,
        )
    finally:
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass
        _pending_http.pop(job_id, None)


async def continue_certbot_dns(job_id: str) -> CertbotResult:
    """DNS-01 işinde kullanıcı TXT ekledikten sonra certbot'u devam ettirir."""
    if job_id not in _pending_dns:
        return CertbotResult(False, None, None, None, None, "Geçersiz veya süresi dolmuş iş")
    entry = _pending_dns[job_id]
    proc = entry["proc"]
    temp_dir = entry["temp_dir"]
    try:
        (temp_dir / "done").write_text("1", encoding="utf-8")
        try:
            await asyncio.wait_for(proc.wait(), timeout=120.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return CertbotResult(False, None, None, None, None, "Certbot zaman aşımı")
        if proc.returncode != 0:
            err = (await proc.stderr.read()).decode("utf-8", errors="replace").strip() if proc.stderr else ""
            return CertbotResult(False, None, None, None, None, err or f"Çıkış kodu: {proc.returncode}")
        sanitized = entry.get("domain") or _sanitize_domain(entry["txt_name"].replace("_acme-challenge.", ""))
        live_dir = CERTBOT_USER_DIR / "live" / sanitized
        cert_path = live_dir / "cert.pem"
        if not cert_path.exists():
            return CertbotResult(False, None, None, None, None, "Sertifika dosyası oluşturulmadı")
        return CertbotResult(
            success=True,
            cert_path=str(cert_path),
            key_path=str(live_dir / "privkey.pem") if (live_dir / "privkey.pem").exists() else None,
            chain_path=str(live_dir / "chain.pem") if (live_dir / "chain.pem").exists() else None,
            fullchain_path=str(live_dir / "fullchain.pem") if (live_dir / "fullchain.pem").exists() else None,
            error=None,
        )
    finally:
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass
        _pending_dns.pop(job_id, None)


def get_pending_http_file(job_id: str) -> tuple[str | None, str | None, str | None]:
    """Bekleyen HTTP-01 işi için domain, dosya adı ve içeriği döndürür."""
    if job_id not in _pending_http:
        return None, None, None
    e = _pending_http[job_id]
    return e.get("domain"), e.get("file_name"), e.get("file_content")


def get_pending_dns_txt(job_id: str) -> tuple[str | None, str | None]:
    """Bekleyen DNS işi için TXT adı ve değerini döndürür."""
    if job_id not in _pending_dns:
        return None, None
    e = _pending_dns[job_id]
    return e.get("txt_name"), e.get("txt_value")


def read_cert_file(file_path: str | Path) -> bytes | None:
    """Sertifika/key dosyasını okur. Dosya yoksa veya okunamazsa None."""
    path = Path(file_path)
    try:
        if not path.exists() or not path.is_file():
            return None
        return path.read_bytes()
    except OSError:
        return None
