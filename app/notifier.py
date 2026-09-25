"""Асинхронные Telegram-уведомления о рисках сертификатов."""

from __future__ import annotations

import html
import logging
import os
from typing import Any

import httpx


logger = logging.getLogger(__name__)
ALERT_STATUSES = {"Warning", "Critical", "Expired"}


def _text(value: Any, fallback: str = "—") -> str:
    if value is None or value == "":
        return fallback
    if isinstance(value, (list, tuple, set)):
        value = "; ".join(str(item) for item in value) or fallback
    return html.escape(str(value))


def format_alert(cert_data: dict, trigger_reason: str) -> str:
    reasons = cert_data.get("risk_reasons") or cert_data.get("reasons") or []
    recommendations = cert_data.get("recommendations") or []
    reason_text = "; ".join(
        part for part in [trigger_reason, "; ".join(map(str, reasons))] if part
    )
    return (
        "🚨 <b>Certificate Radar Alert</b>\n"
        f"• <b>Хост:</b> <code>{_text(cert_data.get('host'))}:{_text(cert_data.get('port', 443))}</code>\n"
        f"• <b>Статус:</b> {_text(cert_data.get('status'))}\n"
        f"• <b>Risk Score:</b> {_text(cert_data.get('risk_score', 0))}/100 "
        f"({_text(cert_data.get('risk_level'))})\n"
        f"• <b>Дней осталось:</b> {_text(cert_data.get('days_left'))}\n"
        f"• <b>Причина:</b> {_text(reason_text)}\n"
        f"• <b>Рекомендация:</b> {_text(recommendations)}"
    )


def alert_trigger(cert_data: dict) -> str | None:
    status = str(cert_data.get("status") or "")
    risk_score = int(cert_data.get("risk_score") or 0)
    triggers: list[str] = []
    if status in ALERT_STATUSES:
        triggers.append(f"Статус изменён на {status}")
    if risk_score >= 50:
        triggers.append(f"Risk Score достиг {risk_score}/100")
    return "; ".join(triggers) or None


async def send_alert(cert_data: dict, trigger_reason: str) -> bool:
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    if not token or not chat_id:
        logger.warning(
            "Telegram alert skipped: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is not configured"
        )
        return False

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": format_alert(cert_data, trigger_reason),
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
        return True
    except httpx.HTTPError as exc:
        logger.error("Telegram alert failed: %s", exc)
        return False
