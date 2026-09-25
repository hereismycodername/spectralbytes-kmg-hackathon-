import importlib
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
import pytest_asyncio


TEST_DB = Path(tempfile.mkdtemp(prefix="certificate-radar-tests-")) / "radar.db"
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{TEST_DB}"
os.environ["SCAN_INTERVAL_HOURS"] = "6"

main_module = importlib.import_module("app.main")
database_module = importlib.import_module("app.database")
TargetResult = importlib.import_module("app.certificate_checker").TargetResult


@pytest_asyncio.fixture
async def client():
    async with database_module.engine.begin() as connection:
        await connection.run_sync(database_module.Base.metadata.drop_all)
    async with main_module.app.router.lifespan_context(main_module.app):
        transport = httpx.ASGITransport(app=main_module.app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
        ) as api_client:
            yield api_client


@pytest.fixture
def mock_scan(monkeypatch):
    async def fake_scan(_targets):
        expires_at = datetime.now(timezone.utc) + timedelta(days=90)
        return [
            TargetResult(
                target="example.com",
                host="example.com",
                port=443,
                status="OK",
                explanation="Сертификат действителен",
                subject_cn="example.com",
                san=["example.com"],
                issuer="CN=Test CA",
                thumbprint="AB" * 32,
                not_valid_after=expires_at,
                days_left=90,
            )
        ]

    monkeypatch.setattr(main_module, "scan_targets", fake_scan)


async def create_certificate(client, mock_scan):
    response = await client.post("/api/scan", json={"targets": ["example.com"]})
    assert response.status_code == 200
    return response.json()[0]


@pytest.mark.asyncio
async def test_get_certificates_starts_empty(client):
    response = await client.get("/api/certificates")
    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.asyncio
async def test_post_scan_saves_certificate(client, mock_scan):
    certificate = await create_certificate(client, mock_scan)
    assert certificate["host"] == "example.com"
    assert certificate["status"] == "OK"
    assert certificate["risk_score"] == 10

    registry = await client.get("/api/certificates")
    assert len(registry.json()) == 1


@pytest.mark.asyncio
async def test_export_csv(client, mock_scan):
    await create_certificate(client, mock_scan)
    response = await client.get("/api/export/csv")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "Risk Score" in response.text
    assert "example.com" in response.text


@pytest.mark.asyncio
async def test_export_csv_uses_custom_filename(client, mock_scan):
    await create_certificate(client, mock_scan)
    response = await client.get(
        "/api/export/csv", params={"filename": "Отчёт жюри.csv"}
    )
    disposition = response.headers["content-disposition"]
    assert "attachment" in disposition
    assert "filename*=UTF-8''" in disposition
    assert "%D0%9E%D1%82%D1%87%D1%91%D1%82-%D0%B6%D1%8E%D1%80%D0%B8.csv" in disposition


@pytest.mark.asyncio
async def test_export_csv_applies_status_and_search_filters(client, monkeypatch):
    async def filtered_scan(_targets):
        now = datetime.now(timezone.utc)
        return [
            TargetResult(
                target="healthy.example.com",
                host="healthy.example.com",
                port=443,
                status="OK",
                subject_cn="healthy.example.com",
                issuer="CN=Healthy CA",
                not_valid_after=now + timedelta(days=90),
                days_left=90,
            ),
            TargetResult(
                target="renew.example.com",
                host="renew.example.com",
                port=443,
                status="Information",
                subject_cn="renew.example.com",
                issuer="CN=Renewal CA",
                not_valid_after=now + timedelta(days=45),
                days_left=45,
            ),
        ]

    monkeypatch.setattr(main_module, "scan_targets", filtered_scan)
    await client.post(
        "/api/scan",
        json={"targets": ["healthy.example.com", "renew.example.com"]},
    )
    response = await client.get(
        "/api/export/csv",
        params={"status": "Information", "search": "renew"},
    )
    assert response.status_code == 200
    assert "renew.example.com" in response.text
    assert "healthy.example.com" not in response.text


@pytest.mark.asyncio
async def test_certificate_history(client, mock_scan):
    certificate = await create_certificate(client, mock_scan)
    response = await client.get(f"/api/certificates/{certificate['id']}/history")
    assert response.status_code == 200
    points = response.json()
    assert len(points) == 1
    assert points[0]["risk_score"] == 10
    assert points[0]["days_left"] == 90


@pytest.mark.asyncio
async def test_telegram_endpoint(client, monkeypatch):
    async def fake_send_alert(_cert_data, _trigger_reason):
        return True

    monkeypatch.setattr(main_module, "send_alert", fake_send_alert)
    response = await client.post("/api/test-telegram")
    assert response.status_code == 200
    assert response.json()["sent"] is True


@pytest.mark.asyncio
async def test_manual_critical_scan_sends_telegram_alert(client, monkeypatch):
    async def critical_scan(_targets):
        return [
            TargetResult(
                target="critical.example.com",
                host="critical.example.com",
                port=443,
                status="Critical",
                subject_cn="critical.example.com",
                days_left=5,
                risk_score=85,
                risk_level="Critical",
            )
        ]

    calls = []

    async def fake_send_alert(cert_data, trigger_reason):
        calls.append((cert_data, trigger_reason))
        return True

    monkeypatch.setattr(main_module, "scan_targets", critical_scan)
    monkeypatch.setattr(main_module, "send_alert", fake_send_alert)
    response = await client.post(
        "/api/scan", json={"targets": ["critical.example.com"]}
    )
    assert response.status_code == 200
    assert len(calls) == 1
    assert calls[0][0]["host"] == "critical.example.com"
