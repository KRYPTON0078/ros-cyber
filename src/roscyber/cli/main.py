"""ROS Cyber CLI."""

import asyncio
import json
from pathlib import Path
from typing import Any

import typer
import httpx
from rich.console import Console
from rich.table import Table

from roscyber.scanner.scanner import run_scan, save_report
from roscyber.shared.config import get_settings

app = typer.Typer(name="roscyber", help="ROS Cyber security platform CLI")
console = Console()


@app.command()
def scan(
    target: str = typer.Option("localhost", "--target", "-t", help="Scan target host"),
    output: str = typer.Option("scan_report.json", "--output", "-o"),
    markdown: str = typer.Option("", "--markdown", "-m"),
) -> None:
    """Run ROS/IoT security misconfiguration scan."""
    console.print(f"[bold blue]ROS Cyber Scanner[/] — target: {target}")
    result = asyncio.run(run_scan(target))
    save_report(result, output)
    if markdown:
        Path(markdown).write_text(result.to_markdown(), encoding="utf-8")
    table = Table(title=f"Findings ({len(result.findings)})")
    table.add_column("ID")
    table.add_column("Severity")
    table.add_column("Title")
    for f in result.findings:
        table.add_row(f.check_id, f.severity, f.title)
    console.print(table)
    console.print(f"[green]Report saved to {output}[/]")


@app.command("demo-seed")
def demo_seed(
    host: str = typer.Option("http://localhost:8000", "--host"),
    policy_host: str = typer.Option("http://localhost:8001", "--policy-host"),
    robot_id: str = typer.Option("robot-alpha", "--robot-id"),
    count: int = typer.Option(5, "--count"),
) -> None:
    """Seed demo telemetry and policy decisions."""
    token = _get_token(host)
    headers = {"Authorization": f"Bearer {token}"}
    console.print("[bold green]Seeding telemetry[/]")
    for i in range(count):
        lat = 14.6 + (i * 0.0005)
        lon = 120.98 + (i * 0.0005)
        payload = {
            "robot_id": robot_id,
            "latitude": lat,
            "longitude": lon,
            "battery_pct": 90,
            "motor_rpm": 650,
        }
        _post_json(f"{host}/v1/telemetry", payload, headers)
    console.print("[bold green]Sending policy commands[/]")
    _post_json(
        f"{policy_host}/v1/commands/evaluate",
        {"robot_id": robot_id, "command_type": "cmd_vel", "linear_x": 0.5, "angular_z": 0.2},
        headers,
    )
    _post_json(
        f"{policy_host}/v1/commands/evaluate",
        {"robot_id": robot_id, "command_type": "cmd_vel", "linear_x": 2.2, "angular_z": 0.4},
        headers,
    )
    console.print("[bold cyan]Demo seed complete. Open http://localhost:8002[/]")


@app.command()
def config() -> None:
    """Show current configuration."""
    settings = get_settings()
    console.print(json.dumps(settings.model_dump(), indent=2, default=str))


@app.command()
def version() -> None:
    from roscyber import __version__

    console.print(f"ROS Cyber v{__version__}")


def _get_token(host: str) -> str:
    payload = {"username": "operator", "password": "operator123!"}
    response = _post_json(f"{host}/v1/auth/token", payload)
    return response.get("access_token", "")


def _post_json(
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    with httpx.Client(timeout=10) as client:
        resp = client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        return resp.json()


if __name__ == "__main__":
    app()
