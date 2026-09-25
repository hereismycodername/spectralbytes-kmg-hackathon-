"""Идемпотентное заполнение базы демонстрационными данными."""

from __future__ import annotations

import asyncio
from datetime import timedelta

from sqlalchemy import delete, select

from app.certificate_checker import build_risk_assessment, status_from_days
from app.database import (
    Certificate,
    CertificateHistory,
    SessionLocal,
    init_db,
    utc_now,
)


DEMO_CERTIFICATES = [
    {
        "host": "google.com",
        "cn": "*.google.com",
        "san": ["google.com", "*.google.com"],
        "issuer": "CN=WR2,O=Google Trust Services,C=US",
        "days": [73, 72, 71, 70, 69],
        "scores": [10, 10, 10, 0, 0],
        "owner": "Demo Team",
    },
    {
        "host": "expired.badssl.com",
        "cn": "*.badssl.com",
        "san": ["*.badssl.com", "badssl.com"],
        "issuer": "CN=COMODO RSA Domain Validation Secure Server CA,O=COMODO CA Limited,C=GB",
        "days": [3, 2, 1, 0, -1],
        "scores": [70, 85, 95, 100, 100],
    },
    {
        "host": "self-signed.badssl.com",
        "cn": "*.badssl.com",
        "san": ["*.badssl.com", "badssl.com"],
        "issuer": "CN=*.badssl.com,O=BadSSL,C=US",
        "days": [731, 730, 729, 728, 727],
        "scores": [10, 10, 35, 35, 35],
        "is_self_signed": True,
        "untrusted_chain": True,
    },
    {
        "host": "wrong.host.badssl.com",
        "cn": "*.badssl.com",
        "san": ["*.badssl.com", "badssl.com"],
        "issuer": "CN=R13,O=Let's Encrypt,C=US",
        "days": [35, 34, 33, 32, 31],
        "scores": [10, 10, 25, 40, 55],
        "hostname_mismatch": True,
    },
    {
        "host": "untrusted-root.badssl.com",
        "cn": "*.badssl.com",
        "san": ["*.badssl.com", "badssl.com"],
        "issuer": "CN=BadSSL Untrusted Root Certificate Authority,O=BadSSL,C=US",
        "days": [731, 730, 729, 728, 727],
        "scores": [10, 10, 35, 35, 35],
        "untrusted_chain": True,
    },
]


async def seed_demo_data() -> int:
    await init_db()
    now = utc_now()

    async with SessionLocal() as session:
        for index, item in enumerate(DEMO_CERTIFICATES, start=1):
            query = select(Certificate).where(
                Certificate.host == item["host"],
                Certificate.port == 443,
            )
            certificate = (await session.execute(query)).scalar_one_or_none()
            if certificate is None:
                certificate = Certificate(host=item["host"], port=443)
                session.add(certificate)

            days_left = item["days"][-1]
            status, explanation = status_from_days(days_left)
            assessment = build_risk_assessment(
                days_left=days_left,
                hostname_mismatch=item.get("hostname_mismatch", False),
                untrusted_chain=item.get("untrusted_chain", False),
                is_self_signed=item.get("is_self_signed", False),
                weak_signature=False,
                weak_key=False,
                owner_assigned=bool(item.get("owner")),
            )

            certificate.cn = item["cn"]
            certificate.san = item["san"]
            certificate.issuer = item["issuer"]
            certificate.thumbprint = f"{index:02X}" * 32
            certificate.not_after = now + timedelta(days=days_left)
            certificate.days_left = days_left
            certificate.status = status
            certificate.explanation = explanation
            certificate.error = None
            certificate.is_self_signed = item.get("is_self_signed", False)
            certificate.hostname_mismatch = item.get("hostname_mismatch", False)
            certificate.weak_signature = False
            certificate.weak_key = False
            certificate.untrusted_chain = item.get("untrusted_chain", False)
            certificate.risk_score = assessment["risk_score"]
            certificate.risk_level = assessment["risk_level"]
            certificate.risk_reasons = assessment["risk_reasons"]
            certificate.recommendations = assessment["recommendations"]
            certificate.owner = item.get("owner")
            certificate.last_scanned_at = now

            await session.flush()
            await session.execute(
                delete(CertificateHistory).where(
                    CertificateHistory.certificate_id == certificate.id
                )
            )
            for offset, (history_days, score) in enumerate(
                zip(item["days"], item["scores"], strict=True)
            ):
                history_status, _ = status_from_days(history_days)
                session.add(
                    CertificateHistory(
                        certificate_id=certificate.id,
                        scanned_at=now - timedelta(days=4 - offset),
                        risk_score=score,
                        days_left=history_days,
                        status=history_status,
                    )
                )

        await session.commit()

    return len(DEMO_CERTIFICATES)


async def _main() -> None:
    count = await seed_demo_data()
    print(f"Demo data ready: {count} certificates, 5 history points each")


if __name__ == "__main__":
    asyncio.run(_main())
