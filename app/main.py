from __future__ import annotations

import csv
import io
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.certificate_checker import TargetResult, build_risk_assessment, scan_targets
from app.database import (
    Certificate,
    CertificateHistory,
    get_session,
    init_db,
    upsert_certificate,
)
from app.scheduler import CertificateScheduler, scan_lock


BASE_DIR = Path(__file__).resolve().parent.parent


@asynccontextmanager
async def lifespan(application: FastAPI):
    await init_db()
    scheduler = CertificateScheduler(application)
    application.state.scheduler = scheduler
    scheduler.start()
    try:
        yield
    finally:
        await scheduler.stop()


app = FastAPI(
    title="Certificate Radar",
    description="Мониторинг TLS/SSL-сертификатов корпоративной инфраструктуры.",
    version="0.4.0",
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


class ScanRequest(BaseModel):
    targets: list[str] = Field(min_length=1)


class OwnerUpdate(BaseModel):
    owner: str | None = Field(default=None, max_length=255)


class CertificateRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    host: str
    port: int
    cn: str | None
    san: list[str]
    issuer: str | None
    thumbprint: str | None
    not_after: datetime | None
    days_left: int | None
    status: str
    explanation: str | None
    error: str | None
    is_self_signed: bool
    hostname_mismatch: bool
    weak_signature: bool
    weak_key: bool
    untrusted_chain: bool
    risk_score: int
    risk_level: str
    risk_reasons: list[str]
    recommendations: list[str]
    owner: str | None
    last_scanned_at: datetime


class CertificateHistoryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    scanned_at: datetime
    risk_score: int
    days_left: int


async def save_results(
    session: AsyncSession,
    results: list[TargetResult],
) -> list[Certificate]:
    certificates = [await upsert_certificate(session, result) for result in results]
    await session.commit()
    for certificate in certificates:
        await session.refresh(certificate)
    return certificates


@app.get("/", name="dashboard")
async def dashboard(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"title": "Certificate Radar", "results": [], "error": None, "targets": ""},
    )


@app.post("/api/scan", response_model=list[CertificateRead])
async def api_scan(
    payload: ScanRequest,
    session: AsyncSession = Depends(get_session),
):
    try:
        async with scan_lock:
            results = await scan_targets(payload.targets)
            return await save_results(session, results)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/certificates", response_model=list[CertificateRead])
async def api_certificates(
    status: str | None = Query(default=None),
    search: str | None = Query(default=None),
    session: AsyncSession = Depends(get_session),
):
    query = select(Certificate).order_by(Certificate.last_scanned_at.desc())

    if status:
        query = query.where(Certificate.status == status)
    if search:
        pattern = f"%{search}%"
        query = query.where(
            or_(
                Certificate.host.ilike(pattern),
                Certificate.cn.ilike(pattern),
                Certificate.issuer.ilike(pattern),
            )
        )

    return list((await session.execute(query)).scalars().all())


@app.get(
    "/api/certificates/{cert_id}/history",
    response_model=list[CertificateHistoryRead],
)
async def certificate_history(
    cert_id: int,
    session: AsyncSession = Depends(get_session),
):
    if await session.get(Certificate, cert_id) is None:
        raise HTTPException(status_code=404, detail="Сертификат не найден")

    query = (
        select(CertificateHistory)
        .where(CertificateHistory.certificate_id == cert_id)
        .order_by(CertificateHistory.scanned_at.asc())
    )
    return list((await session.execute(query)).scalars().all())


@app.get("/api/scheduler/status")
async def scheduler_status(request: Request):
    scheduler: CertificateScheduler = request.app.state.scheduler
    interval = scheduler.interval_hours
    return {
        "next_scan_at": request.app.state.next_scan_at.isoformat(),
        "interval_hours": int(interval) if interval.is_integer() else interval,
    }


@app.patch(
    "/api/certificates/{cert_id}/owner",
    response_model=CertificateRead,
)
async def update_certificate_owner(
    cert_id: int,
    payload: OwnerUpdate,
    session: AsyncSession = Depends(get_session),
):
    certificate = await session.get(Certificate, cert_id)
    if certificate is None:
        raise HTTPException(status_code=404, detail="Сертификат не найден")

    owner = payload.owner.strip() if payload.owner else None
    certificate.owner = owner or None
    assessment = build_risk_assessment(
        days_left=certificate.days_left if certificate.days_left is not None else 0,
        hostname_mismatch=certificate.hostname_mismatch,
        untrusted_chain=certificate.untrusted_chain,
        is_self_signed=certificate.is_self_signed,
        weak_signature=certificate.weak_signature,
        weak_key=certificate.weak_key,
        owner_assigned=bool(certificate.owner),
    )
    if certificate.status == "Error":
        reasons = [
            reason
            for reason in (certificate.risk_reasons or ["Не удалось установить TLS-соединение с сервисом"])
            if "ответствен" not in reason.lower()
        ]
        recommendations = [
            item
            for item in (certificate.recommendations or ["Проверьте DNS, сетевую доступность и настройки TLS"])
            if "ответствен" not in item.lower()
        ]
        if not certificate.owner:
            reasons.append("Для сервиса не назначен ответственный")
            recommendations.append("Назначьте ответственного за сертификат или сервис")
        assessment = {
            "risk_score": 100,
            "risk_level": "Critical",
            "risk_reasons": reasons,
            "recommendations": recommendations,
        }
    certificate.risk_score = assessment["risk_score"]
    certificate.risk_level = assessment["risk_level"]
    certificate.risk_reasons = assessment["risk_reasons"]
    certificate.recommendations = assessment["recommendations"]
    await session.commit()
    await session.refresh(certificate)
    return certificate


@app.get("/api/export/csv")
async def export_certificates_csv(
    session: AsyncSession = Depends(get_session),
):
    query = select(Certificate).order_by(Certificate.host, Certificate.port)
    certificates = list((await session.execute(query)).scalars().all())

    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(
        [
            "Host",
            "Port",
            "CN",
            "Issuer",
            "Expiration Date",
            "Days Left",
            "Status",
            "Risk Score",
            "Risk Level",
            "Is Self-Signed",
            "Hostname Mismatch",
            "Untrusted Chain",
            "Weak Signature",
            "Weak Key",
            "Risk Reasons",
            "Recommendations",
            "Owner",
            "Last Scanned",
        ]
    )

    for certificate in certificates:
        writer.writerow(
            [
                certificate.host,
                certificate.port,
                certificate.cn or "",
                certificate.issuer or "",
                certificate.not_after.isoformat() if certificate.not_after else "",
                certificate.days_left if certificate.days_left is not None else "",
                certificate.status,
                certificate.risk_score,
                certificate.risk_level,
                certificate.is_self_signed,
                certificate.hostname_mismatch,
                certificate.untrusted_chain,
                certificate.weak_signature,
                certificate.weak_key,
                "; ".join(certificate.risk_reasons or []),
                "; ".join(certificate.recommendations or []),
                certificate.owner or "",
                certificate.last_scanned_at.isoformat(),
            ]
        )

    return Response(
        content="\ufeff" + output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": 'attachment; filename="certificate-radar.csv"'
        },
    )


@app.get("/health", tags=["system"])
async def health_check():
    return {"status": "ok"}
