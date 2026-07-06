"""Certbot ile sertifika üretimi."""
import asyncio
import logging
import os
import re
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import NamedTuple

from app.config import CERTBOT_LIVE, CERTBOT_USER_DIR, CERTBOT_USER_WORK, CERTBOT_USER_LOGS

logger = logging.getLogger(__name__)

# Manuel doğrulama bekleyen işler: job_id -> { status, proc, temp_dir, domain_id, ... }
_pending_dns: dict[str, dict] = {}
_pending_http: dict[str, dict] = {}

_PEM_BLOCK_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)


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


# İki parçalı kamu sonekleri: apex tespiti için (imhotep.com.tr -> apex)
_MULTI_LABEL_SUFFIXES = {
    "com.tr", "net.tr", "org.tr", "gen.tr", "web.tr", "info.tr", "biz.tr",
    "av.tr", "dr.tr", "bel.tr", "pol.tr", "edu.tr", "gov.tr", "k12.tr",
    "name.tr", "tv.tr",
    "co.uk", "org.uk", "me.uk", "com.au", "net.au", "org.au",
    "co.nz", "com.br", "com.mx", "co.in", "co.za", "com.cn",
}


def expand_domains(domain: str) -> list[str]:
    """
    Sertifikanın kapsayacağı isim listesi; ilk eleman birincildir (cert-name olur).
    apex -> [apex, www.apex]; www.apex -> [www.apex, apex];
    diğer alt domainler ve wildcard olduğu gibi kalır.
    """
    raw = domain.strip().lower()
    if raw.startswith("*."):
        return [raw]
    d = _sanitize_domain(raw)
    if not d:
        return []
    labels = d.split(".")
    if labels[0] == "www" and len(labels) >= 3:
        return [d, d[4:]]
    is_apex = len(labels) == 2 or (
        len(labels) == 3 and ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES
    )
    if is_apex:
        return [d, f"www.{d}"]
    return [d]


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
        # Mevcut sertifikaya isim eklenirken (örn. www) sormadan genişlet
        "--cert-name",
        sanitized,
        "--expand",
        "--renew-with-new-domains",
    ]
    for name in expand_domains(domain):
        cmd.extend(["-d", name])
    cmd.extend([
        # Root olmadan çalışsın: config/work/logs kullanıcı dizinine yazılır
        "--config-dir",
        str(CERTBOT_USER_DIR),
        "--work-dir",
        str(CERTBOT_USER_WORK),
        "--logs-dir",
        str(CERTBOT_USER_LOGS),
    ])
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
    Geriye uyumluluk: HTTP-01 işini arka planda başlatır ve hazır olana kadar bekler.
    Döner: (job_id, file_name, file_content, error).
    """
    job_id, err = await start_certbot_http_manual(domain, email, domain_id)
    if err or not job_id:
        return None, None, None, err or "İş başlatılamadı"
    for _ in range(180):
        status = get_pending_http_status(job_id)
        if status["status"] == "ready":
            return job_id, status["file_name"], status["file_content"], None
        if status["status"] == "error":
            return None, None, None, status.get("error") or "Certbot hatası"
        await asyncio.sleep(0.5)
    cancel_pending_http_for_domain(domain_id)
    return None, None, None, "Doğrulama dosyası zaman aşımı (90 sn)"


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

    env = {**os.environ, "CERTBOT_DNS_WAIT_DIR": str(temp_dir)}
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


def _register_new_challenges(entry: dict) -> int:
    """
    temp_dir'de hook'un yazdığı yeni doğrulama dosyalarını challenge listesine ekler.
    Birden çok domain (örn. apex + www) için certbot hook'u her domain için ayrı çağırır.
    """
    temp_dir = entry.get("temp_dir")
    if not temp_dir:
        return 0
    known = {c["file_name"] for c in entry.get("challenges", [])}
    new_count = 0
    for val_file in sorted(Path(temp_dir).glob("validation_*")):
        token = val_file.name[len("validation_"):]
        if not token or token in known:
            continue
        domain_file = Path(temp_dir) / f"domain_{token}"
        try:
            challenge_domain = domain_file.read_text(encoding="utf-8").strip() if domain_file.exists() else None
            file_content = val_file.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        entry.setdefault("challenges", []).append({
            "file_name": token,
            "file_content": file_content,
            "domain": challenge_domain or entry.get("domain"),
            "released": False,
        })
        new_count += 1
    if new_count:
        current = entry["challenges"][-1]
        entry["file_name"] = current["file_name"]
        entry["file_content"] = current["file_content"]
        entry["challenge_domain"] = current["domain"]
    return new_count


async def _finalize_http_job(job_id: str, domain_id: int) -> None:
    """Certbot süreci bittiğinde sonucu belirler, DB'yi günceller, geçici dizini siler."""
    entry = _pending_http.get(job_id)
    if not entry:
        return
    proc = entry.get("proc")
    io_task = entry.get("io_task")
    stdout = stderr = b""
    if io_task:
        try:
            stdout, stderr = await io_task
        except Exception:
            pass
    if proc and proc.returncode != 0:
        err = (stderr or stdout or b"").decode("utf-8", errors="replace").strip()
        result = CertbotResult(False, None, None, None, None, err or f"Çıkış kodu: {proc.returncode}")
    else:
        result = get_cert_paths(entry["domain"])
        if not result.success:
            result = CertbotResult(False, None, None, None, None, "Sertifika dosyası oluşturulmadı")
    entry["result"] = result
    entry["success"] = result.success
    entry["error"] = result.error
    entry["status"] = "done" if result.success else "error"
    temp_dir = entry.get("temp_dir")
    if temp_dir:
        shutil.rmtree(temp_dir, ignore_errors=True)
    entry["temp_dir"] = None
    entry["proc"] = None

    if result.success:
        from app.crud import get_domain_by_id, refresh_ssl
        from app.database import AsyncSessionLocal

        async with AsyncSessionLocal() as db:
            domain = await get_domain_by_id(db, domain_id)
            if domain:
                domain.cert_path = result.cert_path
                domain.key_path = result.key_path
                domain.chain_path = result.chain_path
                await refresh_ssl(db, domain)
                await db.commit()


async def continue_certbot_http(job_id: str, domain_id: int) -> CertbotResult | None:
    """
    Kullanıcı doğrulama dosyasını yükledikten sonra certbot'u devam ettirir.
    None dönerse sıradaki domain için yeni bir doğrulama dosyası hazırdır
    (iş bitmedi, durum tekrar 'ready' yapılmalı).
    """
    entry = _pending_http.get(job_id)
    if entry is None:
        return CertbotResult(False, None, None, None, None, "Geçersiz veya süresi dolmuş iş")
    proc = entry.get("proc")
    temp_dir = entry.get("temp_dir")
    if not proc or not temp_dir:
        return CertbotResult(False, None, None, None, None, "İş bilgisi eksik")

    # Bekleyen hook'ları serbest bırak: dosya yüklendi, certbot devam edebilir
    for ch in entry.get("challenges", []):
        if not ch["released"]:
            (Path(temp_dir) / f"done_{ch['file_name']}").write_text("1", encoding="utf-8")
            ch["released"] = True

    io_task = entry.get("io_task")
    for _ in range(600):  # 300 sn
        await asyncio.sleep(0.5)
        if _register_new_challenges(entry):
            return None
        if io_task and io_task.done():
            await _finalize_http_job(job_id, domain_id)
            return entry.get("result")
    proc.kill()
    if io_task:
        try:
            await io_task
        except Exception:
            pass
    result = CertbotResult(False, None, None, None, None, "Certbot zaman aşımı (5 dk)")
    entry["result"] = result
    entry["success"] = False
    entry["error"] = result.error
    entry["status"] = "error"
    shutil.rmtree(temp_dir, ignore_errors=True)
    entry["temp_dir"] = None
    entry["proc"] = None
    return result


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
    """Bekleyen HTTP-01 işi için (doğrulanan) domain, dosya adı ve içeriği döndürür."""
    if job_id not in _pending_http:
        return None, None, None
    e = _pending_http[job_id]
    return e.get("challenge_domain") or e.get("domain"), e.get("file_name"), e.get("file_content")


def get_pending_dns_txt(job_id: str) -> tuple[str | None, str | None]:
    """Bekleyen DNS işi için TXT adı ve değerini döndürür."""
    if job_id not in _pending_dns:
        return None, None
    e = _pending_dns[job_id]
    return e.get("txt_name"), e.get("txt_value")


def read_cert_file(file_path: str | Path) -> bytes | None:
    """Sertifika/key dosyasını okur. Sembolik linkleri çözer."""
    path = Path(file_path)
    try:
        resolved = path.resolve(strict=False)
        if not resolved.is_file():
            return None
        return resolved.read_bytes()
    except OSError:
        return None


def split_pem_blocks(data: bytes) -> list[bytes]:
    """PEM içindeki sertifika bloklarını ayırır."""
    if not data:
        return []
    return _PEM_BLOCK_RE.findall(data)


def read_ca_bundle_bytes(domain: str) -> bytes | None:
    """
    CA bundle (yalnızca ara sertifikalar) döndürür.
    chain.pem bazen fullchain ile aynı içeriğe sahip olabildiği için leaf sertifika ayıklanır.
    """
    result = get_cert_paths(domain)
    if not result.success:
        return None

    cert_blocks = split_pem_blocks(read_cert_file(result.cert_path) or b"")
    leaf = cert_blocks[0] if cert_blocks else None

    chain_data = read_cert_file(result.chain_path) if result.chain_path else None
    if chain_data:
        chain_blocks = split_pem_blocks(chain_data)
        if leaf and chain_blocks and chain_blocks[0] == leaf:
            chain_blocks = chain_blocks[1:]
        if chain_blocks:
            return b"\n".join(chain_blocks) + b"\n"

    fullchain_data = read_cert_file(result.fullchain_path) if result.fullchain_path else None
    if fullchain_data:
        fullchain_blocks = split_pem_blocks(fullchain_data)
        if len(fullchain_blocks) > 1:
            return b"\n".join(fullchain_blocks[1:]) + b"\n"

    return None


def cancel_pending_http_for_domain(domain_id: int) -> None:
    """Aynı domain için bekleyen eski HTTP-01 işlerini iptal eder."""
    stale_ids = [
        job_id
        for job_id, entry in list(_pending_http.items())
        if entry.get("domain_id") == domain_id and entry.get("status") in {"starting", "ready", "running"}
    ]
    for job_id in stale_ids:
        entry = _pending_http.pop(job_id, None)
        if not entry:
            continue
        proc = entry.get("proc")
        if proc and proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        temp_dir = entry.get("temp_dir")
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)
        logger.info("Eski HTTP-01 işi iptal edildi: %s", job_id)


def get_pending_http_status(job_id: str) -> dict:
    """HTTP-01 iş durumunu döndürür."""
    entry = _pending_http.get(job_id)
    if not entry:
        return {"status": "missing"}
    payload = {
        "status": entry.get("status", "unknown"),
        "domain": entry.get("domain"),
        "domains": entry.get("domains"),
        "challenge_domain": entry.get("challenge_domain") or entry.get("domain"),
        "file_name": entry.get("file_name"),
        "file_content": entry.get("file_content"),
        "error": entry.get("error"),
        "success": entry.get("success"),
    }
    if entry.get("status") == "done" and entry.get("result"):
        result = entry["result"]
        payload["success"] = result.success
        payload["error"] = result.error
    return payload


async def _run_certbot_http_manual_task(job_id: str, domain: str, email: str, domain_id: int) -> None:
    """Certbot HTTP-01 sürecini arka planda başlatır."""
    entry = _pending_http.get(job_id)
    if not entry:
        return

    certbot = shutil.which("certbot")
    if not certbot:
        entry["status"] = "error"
        entry["error"] = "certbot bulunamadı. Kurulum: apt install certbot"
        return

    sanitized = _sanitize_domain(domain)
    if not sanitized:
        entry["status"] = "error"
        entry["error"] = "Geçersiz domain"
        return
    domains = expand_domains(domain)
    entry["domains"] = domains

    temp_dir = Path(tempfile.mkdtemp(prefix="certbot_http_"))
    # Hook her domain için ayrı çalışır: token'a özel dosyalara yazar,
    # kendi done_<token> dosyası oluşana dek bekler.
    hook_script = temp_dir / "auth_hook.sh"
    hook_script.write_text(
        "#!/bin/bash\n"
        f'echo "$CERTBOT_DOMAIN" > "{temp_dir}/domain_$CERTBOT_TOKEN"\n'
        f'echo "$CERTBOT_VALIDATION" > "{temp_dir}/validation_$CERTBOT_TOKEN"\n'
        f'while [ ! -f "{temp_dir}/done_$CERTBOT_TOKEN" ]; do sleep 1; done\n'
        "exit 0\n",
        encoding="utf-8",
    )
    hook_script.chmod(0o755)
    entry["temp_dir"] = temp_dir

    cmd = [
        certbot,
        "certonly",
        "--manual",
        "--preferred-challenges",
        "http",
        "--agree-tos",
        "--email",
        email,
        "--cert-name",
        sanitized,
        "--expand",
        "--renew-with-new-domains",
    ]
    for name in domains:
        cmd.extend(["-d", name])
    cmd.extend([
        "--config-dir",
        str(CERTBOT_USER_DIR),
        "--work-dir",
        str(CERTBOT_USER_WORK),
        "--logs-dir",
        str(CERTBOT_USER_LOGS),
        "--manual-auth-hook",
        str(hook_script),
    ])
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=os.environ.copy(),
        )
        entry["proc"] = proc
        entry["io_task"] = asyncio.ensure_future(proc.communicate())
        for _ in range(180):
            await asyncio.sleep(0.5)
            if _register_new_challenges(entry):
                entry["status"] = "ready"
                return
            if entry["io_task"].done():
                # Hiç doğrulama istenmedi: sertifika zaten geçerliydi ya da certbot hata verdi
                await _finalize_http_job(job_id, domain_id)
                return
        proc.kill()
        try:
            await entry["io_task"]
        except Exception:
            pass
        entry["status"] = "error"
        entry["error"] = "Doğrulama dosyası zaman aşımı (90 sn)"
    except Exception as e:
        entry["status"] = "error"
        entry["error"] = str(e)


async def start_certbot_http_manual(domain: str, email: str, domain_id: int) -> tuple[str, str | None]:
    """
    HTTP-01 işini arka planda başlatır.
    Döner: (job_id, error). Hata varsa job_id boş olabilir.
    """
    cancel_pending_http_for_domain(domain_id)
    job_id = str(uuid.uuid4())
    _pending_http[job_id] = {
        "status": "starting",
        "proc": None,
        "io_task": None,
        "temp_dir": None,
        "domain_id": domain_id,
        "domain": _sanitize_domain(domain),
        "domains": None,
        "challenges": [],
        "challenge_domain": None,
        "file_name": None,
        "file_content": None,
        "error": None,
        "result": None,
        "success": None,
    }
    try:
        asyncio.create_task(_run_certbot_http_manual_task(job_id, domain, email, domain_id))
    except RuntimeError:
        return "", "Arka plan görevi başlatılamadı"
    return job_id, None


async def _continue_certbot_http_task(job_id: str, domain_id: int) -> None:
    """Certbot HTTP-01 tamamlama sürecini arka planda yürütür."""
    entry = _pending_http.get(job_id)
    if not entry:
        return
    entry["status"] = "running"
    result = await continue_certbot_http(job_id, domain_id)
    if result is None:
        # Sıradaki domain (örn. www) için yeni doğrulama dosyası hazır
        entry["status"] = "ready"
        return
    if entry.get("status") not in {"done", "error"}:
        # _finalize_http_job çalışmadıysa (örn. iş bilgisi eksik) durumu burada yaz
        entry["result"] = result
        entry["success"] = result.success
        entry["error"] = result.error
        entry["status"] = "done" if result.success else "error"


async def start_continue_certbot_http(job_id: str, domain_id: int) -> tuple[bool, str | None]:
    """Sertifika üretimini arka planda tamamlar."""
    if job_id not in _pending_http:
        return False, "Geçersiz veya süresi dolmuş iş"
    entry = _pending_http[job_id]
    if entry.get("status") in {"running", "done"}:
        return True, None
    if entry.get("status") != "ready":
        return False, "İş henüz hazır değil"
    try:
        asyncio.create_task(_continue_certbot_http_task(job_id, domain_id))
    except RuntimeError:
        return False, "Arka plan görevi başlatılamadı"
    return True, None
