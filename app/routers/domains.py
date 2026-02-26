"""Domain API ve sayfa route'ları."""
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.crud import (
    create_domain,
    delete_domain,
    get_domain_by_id,
    get_domain_by_name,
    get_domains,
    refresh_all_ssl,
    refresh_ssl,
    update_domain,
)
from app.database import get_db
from app.schemas import DomainCreate, DomainResponse, DomainUpdate
from app.config import CERTBOT_EMAIL
from app.certbot_runner import (
    run_certbot_http_manual,
    continue_certbot_http,
    get_pending_http_file,
    get_cert_paths,
    read_cert_file,
)

router = APIRouter(prefix="", tags=["domains"])


@router.get("/", response_class=HTMLResponse)
async def index(request: Request, db: AsyncSession = Depends(get_db)):
    """Ana sayfa: domain listesi."""
    domains = await get_domains(db)
    error = request.query_params.get("error")
    certbot_error = request.query_params.get("certbot_error")
    challenge_job = request.query_params.get("challenge_job")
    domain_id = request.query_params.get("domain_id")
    challenge_domain = challenge_file_name = challenge_file_content = None
    if challenge_job and domain_id:
        challenge_domain, challenge_file_name, challenge_file_content = get_pending_http_file(challenge_job)
    tmpl = request.app.state.templates
    return tmpl.TemplateResponse(
        "index.html",
        {
            "request": request,
            "domains": domains,
            "error": error,
            "certbot_error": certbot_error,
            "challenge_job": challenge_job,
            "challenge_domain_id": int(domain_id) if domain_id and domain_id.isdigit() else None,
            "challenge_domain": challenge_domain,
            "challenge_file_name": challenge_file_name,
            "challenge_file_content": challenge_file_content,
        },
    )


@router.post("/domains/add", response_class=RedirectResponse)
async def add_domain(
    request: Request,
    domain: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    """Yeni domain ekler."""
    domain = (domain or "").strip().lower()
    if not domain:
        return RedirectResponse(
            url=str(request.url_for("index")) + "?error=domain_empty",
            status_code=303,
        )
    existing = await get_domain_by_name(db, domain)
    if existing:
        return RedirectResponse(
            url=str(request.url_for("index")) + "?error=domain_exists",
            status_code=303,
        )
    await create_domain(db, DomainCreate(domain=domain, notes=None))
    return RedirectResponse(url=request.url_for("index"), status_code=303)


@router.post("/domains/{domain_id}/delete", response_class=RedirectResponse)
async def remove_domain(
    request: Request,
    domain_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Domain siler."""
    d = await get_domain_by_id(db, domain_id)
    if not d:
        raise HTTPException(status_code=404, detail="Domain bulunamadı")
    await delete_domain(db, d)
    return RedirectResponse(url=request.url_for("index"), status_code=303)


@router.post("/domains/refresh-all", response_class=RedirectResponse)
async def refresh_all_domain_ssl(request: Request, db: AsyncSession = Depends(get_db)):
    """Tüm domainlerin SSL bilgisini yeniler."""
    await refresh_all_ssl(db)
    return RedirectResponse(url=request.url_for("index"), status_code=303)


@router.post("/domains/{domain_id}/refresh", response_class=RedirectResponse)
async def refresh_domain_ssl(
    request: Request,
    domain_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Yenile: HTTP-01 (dosya yükleme) ile sertifika başlatır. Doğrulama dosyasını domain sunucusuna yüklemeniz yeterli."""
    d = await get_domain_by_id(db, domain_id)
    if not d:
        raise HTTPException(status_code=404, detail="Domain bulunamadı")
    job_id, file_name, file_content, err = await run_certbot_http_manual(
        domain=d.domain,
        email=CERTBOT_EMAIL,
        domain_id=domain_id,
    )
    url = str(request.url_for("index"))
    if err:
        return RedirectResponse(url=url + "?certbot_error=" + quote((err[:400] or "Bilinmeyen hata")), status_code=303)
    return RedirectResponse(url=url + f"?challenge_job={job_id}&domain_id={domain_id}", status_code=303)


@router.post("/domains/{domain_id}/refresh-challenge-continue", response_class=RedirectResponse)
async def refresh_challenge_continue(
    request: Request,
    domain_id: int,
    job_id: str = Form(..., alias="challenge_job"),
    db: AsyncSession = Depends(get_db),
):
    """Doğrulama dosyasını yükledikten sonra sertifika üretimini tamamlar."""
    d = await get_domain_by_id(db, domain_id)
    if not d:
        raise HTTPException(status_code=404, detail="Domain bulunamadı")
    result = await continue_certbot_http(job_id)
    url = str(request.url_for("index"))
    if result.success:
        d.cert_path = result.cert_path
        d.key_path = result.key_path
        d.chain_path = result.chain_path
        await db.flush()
    await refresh_ssl(db, d)
    if not result.success and result.error:
        return RedirectResponse(url=url + "?certbot_error=" + quote((result.error[:400] or "Bilinmeyen hata")), status_code=303)
    return RedirectResponse(url=url, status_code=303)


@router.get("/api/domains", response_model=list[DomainResponse])
async def api_list_domains(db: AsyncSession = Depends(get_db)):
    """API: Tüm domainleri listeler."""
    return await get_domains(db)


@router.post("/api/domains", response_model=DomainResponse)
async def api_create_domain(data: DomainCreate, db: AsyncSession = Depends(get_db)):
    """API: Yeni domain ekler."""
    existing = await get_domain_by_name(db, data.domain)
    if existing:
        raise HTTPException(status_code=400, detail="Bu domain zaten kayıtlı")
    return await create_domain(db, data)


@router.get("/api/domains/{domain_id}", response_model=DomainResponse)
async def api_get_domain(domain_id: int, db: AsyncSession = Depends(get_db)):
    """API: Tek domain getirir."""
    d = await get_domain_by_id(db, domain_id)
    if not d:
        raise HTTPException(status_code=404, detail="Domain bulunamadı")
    return d


@router.post("/api/domains/{domain_id}/refresh", response_model=DomainResponse)
async def api_refresh_ssl(domain_id: int, db: AsyncSession = Depends(get_db)):
    """API: Certbot + SSL yenile."""
    d = await get_domain_by_id(db, domain_id)
    if not d:
        raise HTTPException(status_code=404, detail="Domain bulunamadı")
    result = await run_certbot(
        domain=d.domain,
        email=CERTBOT_EMAIL,
        webroot=CERTBOT_WEBROOT,
        standalone=False,
        dry_run=False,
    )
    if result.success:
        d.cert_path = result.cert_path
        d.key_path = result.key_path
        d.chain_path = result.chain_path
        await db.flush()
    return await refresh_ssl(db, d)


def _download_response(content: bytes | None, filename: str, media_type: str = "application/x-pem-file") -> Response:
    """İndirme yanıtı oluşturur."""
    if content is None:
        raise HTTPException(status_code=404, detail="Dosya bulunamadı veya okunamadı")
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


def _raise_cert_error(result, default_detail: str):
    """get_cert_paths hatasını HTTPException olarak fırlatır."""
    detail = result.error or default_detail
    status = 403 if (result.error and "İzin" in result.error) else 404
    raise HTTPException(status_code=status, detail=detail)


@router.get("/api/domains/{domain_id}/download/cert")
async def download_cert(domain_id: int, db: AsyncSession = Depends(get_db)):
    """Sertifika (cert.pem) indirir — .crt olarak sunar."""
    d = await get_domain_by_id(db, domain_id)
    if not d:
        raise HTTPException(status_code=404, detail="Domain bulunamadı")
    result = get_cert_paths(d.domain)
    if not result.success or not result.cert_path:
        _raise_cert_error(result, "Sertifika dosyası yok")
    content = read_cert_file(result.cert_path)
    filename = d.domain.replace(".", "_") + ".crt"
    return _download_response(content, filename)


@router.get("/api/domains/{domain_id}/download/fullchain")
async def download_fullchain(domain_id: int, db: AsyncSession = Depends(get_db)):
    """Fullchain (cert + chain) indirir — sunucuda tek crt olarak kullanılır."""
    d = await get_domain_by_id(db, domain_id)
    if not d:
        raise HTTPException(status_code=404, detail="Domain bulunamadı")
    result = get_cert_paths(d.domain)
    if not result.success or not result.fullchain_path:
        _raise_cert_error(result, "Fullchain dosyası yok")
    content = read_cert_file(result.fullchain_path)
    filename = d.domain.replace(".", "_") + "_fullchain.crt"
    return _download_response(content, filename)


@router.get("/api/domains/{domain_id}/download/chain")
async def download_chain(domain_id: int, db: AsyncSession = Depends(get_db)):
    """CA bundle (chain.pem) indirir."""
    d = await get_domain_by_id(db, domain_id)
    if not d:
        raise HTTPException(status_code=404, detail="Domain bulunamadı")
    result = get_cert_paths(d.domain)
    if not result.success or not result.chain_path:
        _raise_cert_error(result, "CA bundle dosyası yok")
    content = read_cert_file(result.chain_path)
    filename = d.domain.replace(".", "_") + "_cabundle.pem"
    return _download_response(content, filename)


@router.get("/api/domains/{domain_id}/download/key")
async def download_key(domain_id: int, db: AsyncSession = Depends(get_db)):
    """Private key (privkey.pem) indirir."""
    d = await get_domain_by_id(db, domain_id)
    if not d:
        raise HTTPException(status_code=404, detail="Domain bulunamadı")
    result = get_cert_paths(d.domain)
    if not result.success or not result.key_path:
        _raise_cert_error(result, "Private key dosyası yok")
    content = read_cert_file(result.key_path)
    filename = d.domain.replace(".", "_") + "_private.key"
    return _download_response(content, filename)
