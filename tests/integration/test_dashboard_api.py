"""Integration tests for dashboard API."""

import pytest
from httpx import ASGITransport, AsyncClient

from roscyber.dashboard.app import create_app
from roscyber.shared.config import Settings
from roscyber.shared.database import get_session_factory, init_db
from roscyber.shared.models import CommandAuditLog, RobotTelemetry, SecurityAlert


@pytest.fixture
async def dashboard_app():
    settings = Settings(database_url="sqlite+aiosqlite:///:memory:", profile="hardened")
    _ = settings
    app = create_app()
    await init_db()
    factory = get_session_factory()
    async with factory() as session:
        session.add(
            RobotTelemetry(
                robot_id="robot-alpha",
                latitude=14.6,
                longitude=120.98,
                battery_pct=90,
                motor_rpm=500,
                firmware_version="1.0.0",
            )
        )
        session.add(
            CommandAuditLog(
                robot_id="robot-alpha",
                user_id="operator",
                command_type="cmd_vel",
                payload="{}",
                decision="allow",
                reason="ok",
                correlation_id="test",
            )
        )
        session.add(
            SecurityAlert(
                robot_id="robot-alpha",
                severity="high",
                title="Policy violation",
                description="Denied command",
                mitre_technique="T0855",
                iec_control="SR 3.3",
                raw_event="{}",
            )
        )
        await session.commit()
    return app


@pytest.mark.asyncio
async def test_summary_endpoint(dashboard_app):
    transport = ASGITransport(app=dashboard_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/summary")
        assert resp.status_code == 200
        assert resp.json()["active_robots"] == 1


@pytest.mark.asyncio
async def test_alerts_endpoint(dashboard_app):
    transport = ASGITransport(app=dashboard_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/alerts?limit=5")
        assert resp.status_code == 200
        assert len(resp.json()) >= 1


@pytest.mark.asyncio
async def test_audit_endpoint(dashboard_app):
    transport = ASGITransport(app=dashboard_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/audit?limit=5")
        assert resp.status_code == 200
        assert resp.json()[0]["robot_id"] == "robot-alpha"


@pytest.mark.asyncio
async def test_fleet_endpoint(dashboard_app):
    transport = ASGITransport(app=dashboard_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/fleet")
        assert resp.status_code == 200
        assert resp.json()[0]["robot_id"] == "robot-alpha"


@pytest.mark.asyncio
async def test_alerts_csv(dashboard_app):
    transport = ASGITransport(app=dashboard_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/report/alerts.csv")
        assert resp.status_code == 200
        assert "roscyber_alerts" in resp.headers.get("content-disposition", "")


@pytest.mark.asyncio
async def test_audit_csv(dashboard_app):
    transport = ASGITransport(app=dashboard_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/report/audit.csv")
        assert resp.status_code == 200
        assert "roscyber_audit" in resp.headers.get("content-disposition", "")
