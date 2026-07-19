"""Integration tests for ingestion API."""

import pytest
from httpx import ASGITransport, AsyncClient

from roscyber.ingestion.app import create_app
from roscyber.shared.config import Settings
from roscyber.shared.database import init_db


@pytest.fixture
async def hardened_app(mock_redis):
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        profile="hardened",
        redis_url="redis://localhost:6379/0",
    )
    app = create_app(settings)
    await init_db()
    return app


@pytest.mark.asyncio
async def test_health_endpoint(hardened_app):
    transport = ASGITransport(app=hardened_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"


@pytest.mark.asyncio
async def test_login_and_telemetry(hardened_app):
    transport = ASGITransport(app=hardened_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        login = await client.post(
            "/v1/auth/token",
            json={"username": "operator", "password": "operator123!"},
        )
        assert login.status_code == 200
        token = login.json()["access_token"]
        resp = await client.post(
            "/v1/telemetry",
            json={
                "robot_id": "robot-alpha",
                "latitude": 14.6,
                "longitude": 120.98,
                "battery_pct": 90,
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["robot_id"] == "robot-alpha"


@pytest.mark.asyncio
async def test_unauthenticated_telemetry_rejected(hardened_app):
    transport = ASGITransport(app=hardened_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/v1/telemetry",
            json={"robot_id": "robot-alpha", "latitude": 14.6, "longitude": 120.98},
        )
        assert resp.status_code == 401
