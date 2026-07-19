"""ROS Cyber CLI."""

import asyncio
import json
from pathlib import Path

import typer
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


@app.command()
def config() -> None:
    """Show current configuration."""
    settings = get_settings()
    console.print(json.dumps(settings.model_dump(), indent=2, default=str))


@app.command()
def version() -> None:
    from roscyber import __version__

    console.print(f"ROS Cyber v{__version__}")


if __name__ == "__main__":
    app()
