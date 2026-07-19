#!/usr/bin/env python3
"""Simulated ROS2 fleet publishing telemetry to ingestion API."""

import asyncio
import math
import os
import random
import time

import httpx

INGESTION_URL = os.environ.get("INGESTION_URL", "http://localhost:8000")
ROBOT_IDS = os.environ.get("ROBOT_IDS", "robot-alpha,robot-beta,robot-gamma").split(",")
BASE_LAT = 14.5995
BASE_LON = 120.9842


async def get_token(client: httpx.AsyncClient) -> str:
    resp = await client.post(
        f"{INGESTION_URL}/v1/auth/token",
        json={"username": "operator", "password": "operator123!"},
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


async def publish_telemetry(client: httpx.AsyncClient, token: str, robot_id: str, t: float) -> None:
    lat = BASE_LAT + 0.001 * math.sin(t + hash(robot_id) % 10)
    lon = BASE_LON + 0.001 * math.cos(t + hash(robot_id) % 10)
    payload = {
        "robot_id": robot_id,
        "latitude": lat,
        "longitude": lon,
        "imu_x": random.uniform(-0.1, 0.1),
        "imu_y": random.uniform(-0.1, 0.1),
        "imu_z": 9.81 + random.uniform(-0.05, 0.05),
        "battery_pct": max(10, 100 - (t % 100) * 0.1),
        "motor_rpm": random.uniform(0, 1200),
        "firmware_version": "1.0.0",
    }
    headers = {"Authorization": f"Bearer {token}"}
    await client.post(f"{INGESTION_URL}/v1/telemetry", json=payload, headers=headers)


async def send_command(client: httpx.AsyncClient, token: str, robot_id: str) -> None:
    policy_url = os.environ.get("POLICY_URL", "http://localhost:8001")
    payload = {
        "robot_id": robot_id,
        "command_type": "cmd_vel",
        "linear_x": random.uniform(0, 1.0),
        "angular_z": random.uniform(-0.5, 0.5),
    }
    headers = {"Authorization": f"Bearer {token}"}
    try:
        await client.post(f"{policy_url}/v1/commands/evaluate", json=payload, headers=headers)
    except httpx.HTTPError:
        pass


async def main() -> None:
    print(f"[fleet_simulator] Starting fleet: {ROBOT_IDS}")
    async with httpx.AsyncClient(timeout=10) as client:
        while True:
            try:
                token = await get_token(client)
                t = time.time()
                for robot_id in ROBOT_IDS:
                    await publish_telemetry(client, token, robot_id, t)
                    if random.random() < 0.2:
                        await send_command(client, token, robot_id)
                await asyncio.sleep(2)
            except Exception as exc:
                print(f"[fleet_simulator] Error: {exc}")
                await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(main())
