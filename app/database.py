from __future__ import annotations

from collections.abc import AsyncGenerator
from datetime import datetime, timezone
import os
from pathlib import Path

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    select,
    text,
)
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.certificate_checker import build_risk_assessment, status_from_days


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"sqlite+aiosqlite:///{DATA_DIR / 'radar.db'}",
)


class Base(DeclarativeBase):
    pass


class Certificate(Base):
    __tablename__ = "certificates"
    __table_args__ = (UniqueConstraint("host", "port", name="uq_certificate_host_port"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host: Mapped[str] = mapped_column(String(255), index=True)
    port: Mapped[int] = mapped_column(Integer, default=443)
    cn: Mapped[str | None] = mapped_column(String(255), nullable=True)
    san: Mapped[list[str]] = mapped_column(JSON, default=list)
    issuer: Mapped[str | None] = mapped_column(Text, nullable=True)
    thumbprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    days_left: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_self_signed: Mapped[bool] = mapped_column(Boolean, default=False)
    hostname_mismatch: Mapped[bool] = mapped_column(Boolean, default=False)
    weak_signature: Mapped[bool] = mapped_column(Boolean, default=False)
    weak_key: Mapped[bool] = mapped_column(Boolean, default=False)
    untrusted_chain: Mapped[bool] = mapped_column(Boolean, default=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_level: Mapped[str] = mapped_column(String(16), default="Low")
    risk_reasons: Mapped[list[str]] = mapped_column(JSON, default=list)
    recommendations: Mapped[list[str]] = mapped_column(JSON, default=list)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True, default=None)
    last_scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class CertificateHistory(Base):
    __tablename__ = "certificate_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    certificate_id: Mapped[int] = mapped_column(
        ForeignKey("certificates.id"), index=True, nullable=False
    )
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    days_left: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)


engine: AsyncEngine = create_async_engine(DATABASE_URL, future=True)
SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db() -> None:
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
        columns = {
            row[1]
            for row in (await connection.execute(text("PRAGMA table_info(certificates)"))).all()
        }
        migrations = {
            "weak_signature": "BOOLEAN NOT NULL DEFAULT 0",
            "weak_key": "BOOLEAN NOT NULL DEFAULT 0",
            "untrusted_chain": "BOOLEAN NOT NULL DEFAULT 0",
            "risk_score": "INTEGER NOT NULL DEFAULT 0",
            "risk_level": "VARCHAR(16) NOT NULL DEFAULT 'Low'",
            "risk_reasons": "JSON NOT NULL DEFAULT '[]'",
            "recommendations": "JSON NOT NULL DEFAULT '[]'",
        }
        for column, definition in migrations.items():
            if column not in columns:
                await connection.execute(
                    text(f"ALTER TABLE certificates ADD COLUMN {column} {definition}")
                )

    # Пересчитываем риск для записей, созданных до появления Risk Engine.
    async with SessionLocal() as session:
        certificates = list((await session.execute(select(Certificate))).scalars().all())
        for certificate in certificates:
            if certificate.status == "Error":
                certificate.risk_score = 100
                certificate.risk_level = "Critical"
                certificate.risk_reasons = ["Не удалось установить TLS-соединение с сервисом"]
                certificate.recommendations = [
                    "Проверьте DNS, сетевую доступность и настройки TLS"
                ]
                if not certificate.owner:
                    certificate.risk_reasons.append(
                        "Для сервиса не назначен ответственный"
                    )
                    certificate.recommendations.append(
                        "Назначьте ответственного за сертификат или сервис"
                    )
                continue

            certificate.status, certificate.explanation = status_from_days(
                certificate.days_left if certificate.days_left is not None else 0
            )
            assessment = build_risk_assessment(
                days_left=certificate.days_left if certificate.days_left is not None else 0,
                hostname_mismatch=certificate.hostname_mismatch,
                untrusted_chain=certificate.untrusted_chain,
                is_self_signed=certificate.is_self_signed,
                weak_signature=certificate.weak_signature,
                weak_key=certificate.weak_key,
                owner_assigned=bool(certificate.owner),
            )
            certificate.risk_score = assessment["risk_score"]
            certificate.risk_level = assessment["risk_level"]
            certificate.risk_reasons = assessment["risk_reasons"]
            certificate.recommendations = assessment["recommendations"]
        await session.commit()


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with SessionLocal() as session:
        yield session


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


async def upsert_certificate(session: AsyncSession, result) -> Certificate:
    query = select(Certificate).where(
        Certificate.host == result.host,
        Certificate.port == result.port,
    )
    certificate = (await session.execute(query)).scalar_one_or_none()
    if certificate is None:
        certificate = Certificate(
            host=result.host,
            port=result.port,
            san=[],
            is_self_signed=False,
            hostname_mismatch=False,
        )
        session.add(certificate)

    # Поля, обновляемые всегда
    certificate.status = result.status
    certificate.explanation = result.explanation
    certificate.error = result.error
    certificate.last_scanned_at = utc_now()

    # Поля сертификата — только при успешном подключении
    if result.status != "Error":
        certificate.cn = result.subject_cn
        certificate.san = result.san or []
        certificate.issuer = result.issuer
        certificate.thumbprint = result.thumbprint
        certificate.not_after = result.not_valid_after
        certificate.days_left = result.days_left
        certificate.is_self_signed = result.is_self_signed
        certificate.hostname_mismatch = result.hostname_mismatch

    certificate.weak_signature = result.weak_signature
    certificate.weak_key = result.weak_key
    certificate.untrusted_chain = result.untrusted_chain
    assessment = build_risk_assessment(
        days_left=result.days_left if result.days_left is not None else 0,
        hostname_mismatch=result.hostname_mismatch,
        untrusted_chain=result.untrusted_chain,
        is_self_signed=result.is_self_signed,
        weak_signature=result.weak_signature,
        weak_key=result.weak_key,
        owner_assigned=bool(certificate.owner),
    )
    if result.status == "Error":
        assessment = {
            "risk_score": 100,
            "risk_level": "Critical",
            "risk_reasons": result.risk_reasons,
            "recommendations": result.recommendations,
        }
        if certificate.owner:
            assessment["risk_reasons"] = [
                reason for reason in assessment["risk_reasons"] if "ответствен" not in reason.lower()
            ]
            assessment["recommendations"] = [
                item for item in assessment["recommendations"] if "ответствен" not in item.lower()
            ]

    certificate.risk_score = assessment["risk_score"]
    certificate.risk_level = assessment["risk_level"]
    certificate.risk_reasons = assessment["risk_reasons"]
    certificate.recommendations = assessment["recommendations"]

    await session.flush()
    session.add(
        CertificateHistory(
            certificate_id=certificate.id,
            scanned_at=certificate.last_scanned_at,
            risk_score=certificate.risk_score,
            days_left=result.days_left if result.days_left is not None else 0,
            status=certificate.status,
        )
    )

    return certificate
