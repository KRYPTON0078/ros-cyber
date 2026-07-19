"""Integration tests for policy API."""

import pytest
from httpx import ASGITransport, AsyncClient

from roscyber.policy.app import create_app
from roscyber.shared.config import Settings
from roscyber.shared.database import init_db


@pytest.fixture
async def policy_app(mock_redis, tmp_path):
    policy_file = tmp_path / "cmd_vel.yaml"
    policy_file.write_text(
        "rules:\n  - name: max_linear_velocity\n    type: field_limit\n    field: linear.x\n    max: 1.5\n",
        encoding="utf-8",
    )
    import roscyber.policy.app as policy_module

    policy_module.engine = __import__(
        "roscyber.policy.engine", fromlist=["PolicyEngine"]
    ).PolicyEngine(policies_dir=str(tmp_path))
    settings = Settings(database_url="sqlite+aiosqlite:///:memory:", profile="hardened")
    _ = settings
    app = create_app()
    await init_db()
    return app


@pytest.mark.asyncio
async def test_policy_blocks_fast_command(policy_app, mock_redis):
    transport = ASGITransport(app=policy_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        login = await client.post(
            "http://ingestion:8000/v1/auth/token",
            json={"username": "admin", "password": "admin123!"},
        )
        # Use direct token creation path via ingestion not available — use policy with mock auth
        from roscyber.ingestion.auth import Role, create_access_token

        token = create_access_token("admin", Role.ADMIN)
        resp = await client.post(
            "/v1/commands/evaluate",
            json={"robot_id": "robot-alpha", "command_type": "cmd_vel", "linear_x": 3.0},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["approved"] is False


@pytest.mark.asyncio
async def test_kill_switch_endpoint(policy_app, mock_redis):
    transport = ASGITransport(app=policy_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        from roscyber.ingestion.auth import Role, create_access_token

        token = create_access_token("admin", Role.ADMIN)
        resp = await client.post("/v1/kill-switch/on", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["kill_switch_active"] is True
