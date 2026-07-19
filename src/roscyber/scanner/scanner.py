"""ROS/IoT security scanner."""

import json
import socket
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx

from roscyber.shared.config import get_settings


@dataclass
class ScanFinding:
    check_id: str
    title: str
    severity: str
    description: str
    remediation: str


@dataclass
class ScanResult:
    target: str
    findings: list[ScanFinding] = field(default_factory=list)
    scanned_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "scanned_at": self.scanned_at,
            "findings_count": len(self.findings),
            "findings": [f.__dict__ for f in self.findings],
        }

    def to_markdown(self) -> str:
        lines = [f"# ROS Cyber Scan Report — {self.target}", f"Scanned: {self.scanned_at}", ""]
        for f in self.findings:
            lines += [f"## [{f.severity}] {f.title}", f.description, f"**Remediation:** {f.remediation}", ""]
        return "\n".join(lines)


class SecurityScanner:
    def __init__(self, target: str) -> None:
        self.target = target
        self.settings = get_settings()

    async def run(self) -> ScanResult:
        result = ScanResult(target=self.target)
        await self._check_api_default_creds(result)
        await self._check_cleartext_api(result)
        await self._check_rosbridge(result)
        await self._check_dds_discovery(result)
        await self._check_unsigned_topics(result)
        await self._check_outdated_firmware(result)
        return result

    async def _check_api_default_creds(self, result: ScanResult) -> None:
        url = f"http://{self.target}:8000/v1/auth/token"
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.post(url, json={"username": "admin", "password": "admin123!"})
                if resp.status_code == 200:
                    result.findings.append(
                        ScanFinding(
                            check_id="IOT-001",
                            title="Default credentials accepted",
                            severity="CRITICAL",
                            description="admin/admin123! login succeeded on ingestion API",
                            remediation="Rotate credentials; enforce strong password policy",
                        )
                    )
        except httpx.HTTPError:
            pass

    async def _check_cleartext_api(self, result: ScanResult) -> None:
        url = f"http://{self.target}:8000/health"
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    result.findings.append(
                        ScanFinding(
                            check_id="IOT-002",
                            title="API served over cleartext HTTP",
                            severity="HIGH",
                            description="Ingestion API responds without TLS",
                            remediation="Terminate TLS at reverse proxy; enforce HTTPS",
                        )
                    )
        except httpx.HTTPError:
            pass

    async def _check_rosbridge(self, result: ScanResult) -> None:
        port = 9090
        try:
            sock = socket.create_connection((self.target, port), timeout=2)
            sock.close()
            result.findings.append(
                ScanFinding(
                    check_id="ROS-001",
                    title="rosbridge WebSocket exposed without TLS",
                    severity="CRITICAL",
                    description=f"Port {port} open — unauthenticated rosbridge access likely",
                    remediation="Enable WSS + token auth; restrict network ACLs",
                )
            )
        except OSError:
            pass

    async def _check_dds_discovery(self, result: ScanResult) -> None:
        for port in (7400, 7401):
            try:
                sock = socket.create_connection((self.target, port), timeout=1)
                sock.close()
                result.findings.append(
                    ScanFinding(
                        check_id="ROS-002",
                        title="DDS discovery port exposed",
                        severity="HIGH",
                        description=f"DDS port {port} reachable — domain 0 discovery may leak topics",
                        remediation="Enable SROS2; segment robot VLAN; restrict multicast",
                    )
                )
                break
            except OSError:
                pass

    async def _check_unsigned_topics(self, result: ScanResult) -> None:
        if self.settings.profile != "hardened":
            result.findings.append(
                ScanFinding(
                    check_id="ROS-003",
                    title="SROS2 not enforced on ROS2 topics",
                    severity="HIGH",
                    description="Running in non-hardened profile — cmd_vel topics may be unsigned",
                    remediation="Enable SROS2 keystore; sign /cmd_vel and /odom topics",
                )
            )

    async def _check_outdated_firmware(self, result: ScanResult) -> None:
        url = f"http://{self.target}:8000/v1/robots/robot-alpha/telemetry"
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                token_resp = await client.post(
                    f"http://{self.target}:8000/v1/auth/token",
                    json={"username": "admin", "password": "admin123!"},
                )
                if token_resp.status_code != 200:
                    return
                token = token_resp.json()["access_token"]
                if self.settings.profile == "vulnerable":
                    resp = await client.get(url.replace("robot-alpha", "robot-beta"), headers={})
                else:
                    resp = await client.get(url, headers={"Authorization": f"Bearer {token}"})
                if resp.status_code == 200:
                    data = resp.json()
                    if data and data[0].get("firmware_version", "9.9.9") < "1.2.0":
                        result.findings.append(
                            ScanFinding(
                                check_id="IOT-003",
                                title="Outdated robot firmware detected",
                                severity="MEDIUM",
                                description=f"Firmware {data[0].get('firmware_version')} below minimum 1.2.0",
                                remediation="Apply OTA firmware update; maintain SBOM",
                            )
                        )
        except (httpx.HTTPError, KeyError, IndexError):
            pass


async def run_scan(target: str) -> ScanResult:
    scanner = SecurityScanner(target)
    return await scanner.run()


def save_report(result: ScanResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2)
