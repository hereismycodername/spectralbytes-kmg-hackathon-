"""Фоновое сканирование сохранённых TLS-сервисов."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
from datetime import timedelta
from typing import Any

from sqlalchemy import select

from app.certificate_checker import scan_targets
from app.database import Certificate, SessionLocal, upsert_certificate, utc_now
from app.notifier import alert_trigger, send_alert


logger = logging.getLogger(__name__)
scan_lock = asyncio.Lock()


def _configured_interval_hours() -> float:
    try:
        return max(float(os.getenv("SCAN_INTERVAL_HOURS", "6")), 1 / 60)
    except ValueError:
        return 6.0


def _target(host: str, port: int) -> str:
    try:
        is_ipv6 = ipaddress.ip_address(host).version == 6
    except ValueError:
        is_ipv6 = False
    return f"[{host}]:{port}" if is_ipv6 else f"{host}:{port}"


class CertificateScheduler:
    def __init__(self, application: Any, interval_hours: float | None = None) -> None:
        self.application = application
        self.interval_hours = interval_hours or _configured_interval_hours()
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        if self._task is not None:
            return
        self._set_next_scan()
        self._task = asyncio.create_task(self._run(), name="certificate-auto-scan")

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        self._task = None

    def _set_next_scan(self) -> None:
        self.application.state.next_scan_at = utc_now() + timedelta(
            hours=self.interval_hours
        )

    async def _run(self) -> None:
        while True:
            next_scan_at = self.application.state.next_scan_at
            delay = max(0.0, (next_scan_at - utc_now()).total_seconds())
            await asyncio.sleep(delay)
            try:
                await self.scan_all()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Ошибка автоматического сканирования сертификатов")
            finally:
                self._set_next_scan()

    async def scan_all(self) -> int:
        async with scan_lock:
            async with SessionLocal() as session:
                rows = list(
                    (
                        await session.execute(
                            select(Certificate.host, Certificate.port).order_by(
                                Certificate.id
                            )
                        )
                    ).all()
                )

            if not rows:
                return 0

            results = await scan_targets([_target(host, port) for host, port in rows])
            alerts: list[tuple[dict, str]] = []
            async with SessionLocal() as session:
                for result in results:
                    certificate = await upsert_certificate(session, result)
                    cert_data = {
                        "host": certificate.host,
                        "port": certificate.port,
                        "status": certificate.status,
                        "risk_score": certificate.risk_score,
                        "risk_level": certificate.risk_level,
                        "days_left": certificate.days_left,
                        "risk_reasons": certificate.risk_reasons,
                        "recommendations": certificate.recommendations,
                    }
                    trigger = alert_trigger(cert_data)
                    if trigger:
                        alerts.append(
                            (
                                cert_data,
                                trigger,
                            )
                        )
                await session.commit()

            if alerts:
                await asyncio.gather(
                    *(send_alert(cert_data, reason) for cert_data, reason in alerts)
                )
            return len(results)
