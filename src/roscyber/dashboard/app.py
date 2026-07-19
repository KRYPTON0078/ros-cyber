"""SOC dashboard with WebSocket live alerts."""

import asyncio
import json
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from sqlalchemy import desc, func, select

from roscyber import __version__
from roscyber.ingestion.schemas import HealthResponse
from roscyber.shared.config import get_settings
from roscyber.shared.database import get_session_factory, init_db
from roscyber.shared.logging import configure_logging, get_logger
from roscyber.shared.metrics import metrics_response
from roscyber.shared.models import CommandAuditLog, RobotTelemetry, ScanReport, SecurityAlert
from roscyber.shared.redis_client import get_redis

configure_logging()
logger = get_logger("dashboard")

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>ROS Cyber SOC</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #e6edf3; }
    header { background: #161b22; padding: 1rem 2rem; border-bottom: 1px solid #30363d; display: flex; justify-content: space-between; align-items: center; }
    header h1 { font-size: 1.4rem; color: #58a6ff; }
    .badge { background: #238636; padding: 0.2rem 0.6rem; border-radius: 12px; font-size: 0.75rem; }
    main { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; padding: 1rem 2rem; }
    .panel { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem; }
    .panel h2 { font-size: 0.9rem; color: #8b949e; margin-bottom: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }
    .alert { padding: 0.6rem; border-left: 3px solid #f85149; margin-bottom: 0.5rem; background: #0d1117; border-radius: 4px; font-size: 0.85rem; }
    .alert.critical { border-color: #f85149; }
    .alert.high { border-color: #db6d28; }
    .alert.medium { border-color: #d29922; }
    .alert.low { border-color: #58a6ff; }
    .stat-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.5rem; }
    .stat { text-align: center; padding: 0.8rem; background: #0d1117; border-radius: 6px; }
    .stat .val { font-size: 1.8rem; font-weight: bold; color: #58a6ff; }
    .stat .lbl { font-size: 0.75rem; color: #8b949e; }
    table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
    th, td { padding: 0.4rem; text-align: left; border-bottom: 1px solid #21262d; }
    th { color: #8b949e; }
    #map { height: 200px; background: #0d1117; border-radius: 6px; display: flex; align-items: center; justify-content: center; color: #484f58; }
    .full { grid-column: 1 / -1; }
  </style>
</head>
<body>
  <header>
    <h1>ROS Cyber — Security Operations Center</h1>
    <span class="badge" id="ws-status">Connecting...</span>
  </header>
  <main>
    <div class="panel">
      <h2>Fleet Status</h2>
      <div class="stat-grid">
        <div class="stat"><div class="val" id="robot-count">-</div><div class="lbl">Active Robots</div></div>
        <div class="stat"><div class="val" id="alert-count">-</div><div class="lbl">Open Alerts</div></div>
        <div class="stat"><div class="val" id="scan-count">-</div><div class="lbl">Scan Findings</div></div>
      </div>
    </div>
    <div class="panel">
      <h2>SROS2 / Compliance</h2>
      <div id="compliance">Profile: <strong id="profile">hardened</strong><br/>Kill Switch: <strong id="kill">OFF</strong><br/>Last Scan: <strong id="last-scan">-</strong></div>
    </div>
    <div class="panel full">
      <h2>Live Alert Feed</h2>
      <div id="alerts"><div class="alert medium">Waiting for events...</div></div>
    </div>
    <div class="panel">
      <h2>Fleet Map (GPS)</h2>
      <div id="map">Robot positions loading...</div>
      <table id="fleet-table"><thead><tr><th>Robot</th><th>Lat</th><th>Lon</th><th>Battery</th></tr></thead><tbody></tbody></table>
    </div>
    <div class="panel">
      <h2>Recent Audit Log</h2>
      <table id="audit-table"><thead><tr><th>Robot</th><th>Decision</th><th>Reason</th></tr></thead><tbody></tbody></table>
    </div>
  </main>
  <script>
    const alertsEl = document.getElementById('alerts');
    const wsStatus = document.getElementById('ws-status');

    function addAlert(a) {
      const div = document.createElement('div');
      div.className = 'alert ' + (a.severity || 'medium');
      div.innerHTML = `<strong>[${a.mitre || 'T0000'}] ${a.title}</strong><br/><small>${a.robot_id} — ${a.description || ''}</small>`;
      alertsEl.insertBefore(div, alertsEl.firstChild);
      if (alertsEl.children.length > 20) alertsEl.removeChild(alertsEl.lastChild);
    }

    async function refreshStats() {
      const r = await fetch('/api/v1/summary');
      const d = await r.json();
      document.getElementById('robot-count').textContent = d.active_robots;
      document.getElementById('alert-count').textContent = d.open_alerts;
      document.getElementById('scan-count').textContent = d.scan_findings;
      document.getElementById('profile').textContent = d.profile;
      document.getElementById('kill').textContent = d.kill_switch ? 'ON' : 'OFF';
      document.getElementById('last-scan').textContent = d.last_scan || 'Never';
      const tbody = document.querySelector('#fleet-table tbody');
      tbody.innerHTML = d.fleet.map(r => `<tr><td>${r.robot_id}</td><td>${r.latitude.toFixed(4)}</td><td>${r.longitude.toFixed(4)}</td><td>${r.battery_pct}%</td></tr>`).join('');
      document.getElementById('map').textContent = d.fleet.length ? d.fleet.map(r => r.robot_id + ' @ ' + r.latitude.toFixed(2) + ',' + r.longitude.toFixed(2)).join(' | ') : 'No robots';
      const audit = document.querySelector('#audit-table tbody');
      audit.innerHTML = d.audit.map(a => `<tr><td>${a.robot_id}</td><td>${a.decision}</td><td>${a.reason}</td></tr>`).join('');
      d.recent_alerts.forEach(addAlert);
    }

    const ws = new WebSocket(`ws://${location.host}/ws/alerts`);
    ws.onopen = () => { wsStatus.textContent = 'Live'; wsStatus.style.background = '#238636'; };
    ws.onclose = () => { wsStatus.textContent = 'Disconnected'; wsStatus.style.background = '#da3633'; };
    ws.onmessage = (e) => { addAlert(JSON.parse(e.data)); };
    refreshStats();
    setInterval(refreshStats, 5000);
  </script>
</body>
</html>"""


class ConnectionManager:
    def __init__(self) -> None:
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, data: dict[str, Any]) -> None:
        for ws in list(self.active):
            try:
                await ws.send_json(data)
            except Exception:
                self.disconnect(ws)


manager = ConnectionManager()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="ROS Cyber Dashboard", version=__version__)

    @app.on_event("startup")
    async def startup() -> None:
        await init_db()
        asyncio.create_task(_alert_listener())

    async def _alert_listener() -> None:
        redis = await get_redis()
        last_id = "$"
        while True:
            try:
                result = await redis.xread({settings.alert_stream: last_id}, count=10, block=5000)
                for _stream, messages in result:
                    for msg_id, data in messages:
                        last_id = msg_id
                        factory = get_session_factory()
                        async with factory() as session:
                            alert_id = int(data.get("alert_id", 0))
                            alert = await session.get(SecurityAlert, alert_id)
                            if alert:
                                await manager.broadcast(
                                    {
                                        "alert_id": alert.id,
                                        "severity": alert.severity,
                                        "title": alert.title,
                                        "description": alert.description,
                                        "robot_id": alert.robot_id,
                                        "mitre": alert.mitre_technique,
                                    }
                                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("alert_listener_error", error=str(exc))
                await asyncio.sleep(2)

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse(status="healthy", service="dashboard", version=__version__)

    @app.get("/metrics")
    async def metrics() -> Response:
        return PlainTextResponse(metrics_response(), media_type="text/plain")

    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        return HTMLResponse(DASHBOARD_HTML)

    @app.get("/api/v1/summary")
    async def summary() -> dict[str, Any]:
        factory = get_session_factory()
        async with factory() as session:
            robots = (
                await session.execute(
                    select(RobotTelemetry).distinct(RobotTelemetry.robot_id).order_by(
                        RobotTelemetry.robot_id, RobotTelemetry.id.desc()
                    )
                )
            ).scalars().all()
            open_alerts = (
                await session.execute(
                    select(func.count()).select_from(SecurityAlert).where(SecurityAlert.acknowledged.is_(False))
                )
            ).scalar() or 0
            recent = (
                await session.execute(select(SecurityAlert).order_by(desc(SecurityAlert.id)).limit(10))
            ).scalars().all()
            audit = (
                await session.execute(select(CommandAuditLog).order_by(desc(CommandAuditLog.id)).limit(10))
            ).scalars().all()
            last_scan = (
                await session.execute(select(ScanReport).order_by(desc(ScanReport.id)).limit(1))
            ).scalar_one_or_none()
        return {
            "active_robots": len(robots),
            "open_alerts": open_alerts,
            "scan_findings": last_scan.findings_count if last_scan else 0,
            "profile": settings.profile,
            "kill_switch": settings.kill_switch_active,
            "last_scan": last_scan.created_at.isoformat() if last_scan else None,
            "fleet": [
                {
                    "robot_id": r.robot_id,
                    "latitude": r.latitude,
                    "longitude": r.longitude,
                    "battery_pct": r.battery_pct,
                }
                for r in robots
            ],
            "recent_alerts": [
                {
                    "severity": a.severity,
                    "title": a.title,
                    "description": a.description,
                    "robot_id": a.robot_id,
                    "mitre": a.mitre_technique,
                }
                for a in recent
            ],
            "audit": [{"robot_id": a.robot_id, "decision": a.decision, "reason": a.reason} for a in audit],
        }

    @app.websocket("/ws/alerts")
    async def ws_alerts(websocket: WebSocket) -> None:
        await manager.connect(websocket)
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            manager.disconnect(websocket)

    return app


app = create_app()
