"""Additional unit tests for coverage."""

import os
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from roscyber.cli.main import app as cli_app
from roscyber.dashboard.app import create_app as create_dashboard
from roscyber.detection.worker import _parse_value
from roscyber.ingestion.app import create_app as create_ingestion
from roscyber.policy.app import create_app as create_policy
from roscyber.scanner.scanner import ScanFinding, ScanResult, SecurityScanner
from roscyber.shared.config import get_settings
from roscyber.shared.metrics import metrics_response


def test_parse_value_json():
    assert _parse_value('{"a": 1}') == {"a": 1}


def test_parse_value_plain():
    assert _parse_value("hello") == "hello"


def test_metrics_response():
    data = metrics_response()
    assert isinstance(data, bytes)


def test_cli_version():
    from typer.testing import CliRunner

    runner = CliRunner()
    result = runner.invoke(cli_app, ["version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.stdout


def test_cli_config():
    from typer.testing import CliRunner

    runner = CliRunner()
    result = runner.invoke(cli_app, ["config"])
    assert result.exit_code == 0
    assert "ROS Cyber" in result.stdout


@pytest.mark.asyncio
async def test_dashboard_health(mock_redis):
    os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
    app = create_dashboard()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health")
        assert resp.status_code == 200


@pytest.mark.asyncio
async def test_vulnerable_ingestion_admin(mock_redis, monkeypatch):
    monkeypatch.setenv("ROSCYBER_PROFILE", "vulnerable")
    get_settings.cache_clear()
    from roscyber.shared.config import Settings

    app = create_ingestion(
        Settings(database_url="sqlite+aiosqlite:///:memory:", profile="vulnerable")
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/v1/admin/config")
        assert resp.status_code == 200
        assert "jwt_secret" in resp.json()
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_scanner_sros2_finding(monkeypatch):
    monkeypatch.setenv("ROSCYBER_PROFILE", "vulnerable")
    get_settings.cache_clear()
    scanner = SecurityScanner("127.0.0.1")
    result = ScanResult(target="lab", findings=[])
    await scanner._check_unsigned_topics(result)
    assert any(f.check_id == "ROS-003" for f in result.findings)
    get_settings.cache_clear()


def test_scan_markdown_contains_title():
    result = ScanResult(
        target="lab",
        findings=[ScanFinding("IOT-001", "Test Finding", "HIGH", "desc", "fix")],
    )
    assert "Test Finding" in result.to_markdown()


@pytest.mark.asyncio
async def test_policy_reload(mock_redis, tmp_path):
    policy_file = tmp_path / "cmd_vel.yaml"
    policy_file.write_text(
        "rules:\n  - name: max_linear_velocity\n    type: field_limit\n    field: linear.x\n    max: 1.5\n",
        encoding="utf-8",
    )
    import roscyber.policy.app as policy_module

    policy_module.engine = __import__(
        "roscyber.policy.engine", fromlist=["PolicyEngine"]
    ).PolicyEngine(policies_dir=str(tmp_path))
    app = create_policy()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        from roscyber.ingestion.auth import Role, create_access_token

        token = create_access_token("admin", Role.ADMIN)
        resp = await client.post("/v1/policies/reload", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["rules_loaded"] >= 1
