import pytest

from app.notifier import alert_trigger, format_alert, send_alert


def test_format_alert_escapes_html():
    message = format_alert(
        {
            "host": "<example.com>",
            "port": 443,
            "status": "Critical",
            "risk_score": 90,
            "risk_level": "Critical",
            "days_left": 3,
            "risk_reasons": ["Mismatch <unsafe>"],
            "recommendations": ["Перевыпустить & проверить"],
        },
        "Risk изменился",
    )
    assert "<b>Certificate Radar Alert</b>" in message
    assert "&lt;example.com&gt;" in message
    assert "&lt;unsafe&gt;" in message
    assert "Перевыпустить &amp; проверить" in message


@pytest.mark.asyncio
async def test_missing_telegram_settings_skip_sending(monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
    assert await send_alert({}, "test") is False


def test_alert_trigger_matches_status_or_score():
    assert alert_trigger({"status": "Warning", "risk_score": 20})
    assert alert_trigger({"status": "OK", "risk_score": 50})
    assert alert_trigger({"status": "OK", "risk_score": 49}) is None
