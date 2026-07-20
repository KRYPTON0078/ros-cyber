"""SOC dashboard with WebSocket live alerts."""

import asyncio
import csv
import io
import json
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, PlainTextResponse, Response, StreamingResponse
from sqlalchemy import desc, func, select

from roscyber import __version__
from roscyber.ingestion.auth import User, get_current_user
from roscyber.ingestion.schemas import HealthResponse
from roscyber.shared.config import get_settings
from roscyber.shared.database import get_session_factory, init_db
from roscyber.shared.logging import configure_logging, get_logger
from roscyber.shared.metrics import metrics_response
from roscyber.shared.models import CommandAuditLog, RobotTelemetry, ScanReport, SecurityAlert
from roscyber.shared.redis_client import get_redis

configure_logging()
logger = get_logger("dashboard")
START_TIME = datetime.now(timezone.utc)

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>ROS Cyber SOC</title>
  <link
    rel="stylesheet"
    href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"
    integrity="sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY="
    crossorigin=""
  />
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: #0d1117;
      color: #e6edf3;
    }
    header {
      background: #0f1623;
      padding: 1.2rem 2rem;
      border-bottom: 1px solid #1f2937;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    header h1 {
      font-size: 1.45rem;
      color: #58a6ff;
    }
    header p {
      font-size: 0.85rem;
      color: #8b949e;
      margin-top: 0.35rem;
    }
    .badge {
      background: #238636;
      padding: 0.25rem 0.7rem;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 600;
    }
    .layout {
      padding: 1.2rem 2rem 2rem;
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1rem;
    }
    .panel {
      background: #111827;
      border: 1px solid #1f2937;
      border-radius: 10px;
      padding: 1rem 1.2rem;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.2);
    }
    .panel h2 {
      font-size: 0.8rem;
      color: #94a3b8;
      margin-bottom: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }
    .stat-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 0.7rem;
    }
    .stat {
      text-align: left;
      padding: 0.9rem;
      background: #0b1220;
      border-radius: 8px;
      border: 1px solid #1f2937;
    }
    .stat .val {
      font-size: 1.6rem;
      font-weight: 700;
      color: #58a6ff;
    }
    .stat .lbl {
      font-size: 0.75rem;
      color: #9ca3af;
    }
    .pill-row {
      display: flex;
      gap: 0.5rem;
      flex-wrap: wrap;
    }
    .pill {
      background: #0b1220;
      border: 1px solid #1f2937;
      border-radius: 999px;
      padding: 0.35rem 0.6rem;
      font-size: 0.75rem;
      color: #e6edf3;
    }
    select {
      background: #0b1220;
      color: #e5e7eb;
      border: 1px solid #1f2937;
      border-radius: 6px;
      padding: 0.2rem 0.4rem;
      margin-left: 0.4rem;
    }
    input {
      background: #0b1220;
      color: #e5e7eb;
      border: 1px solid #1f2937;
      border-radius: 6px;
      padding: 0.3rem 0.5rem;
      font-size: 0.8rem;
    }
    .alert {
      padding: 0.65rem 0.75rem;
      border-left: 3px solid #f85149;
      margin-bottom: 0.5rem;
      background: #0b1220;
      border-radius: 6px;
      font-size: 0.85rem;
    }
    .alert.critical { border-color: #f85149; }
    .alert.high { border-color: #db6d28; }
    .alert.medium { border-color: #d29922; }
    .alert.low { border-color: #58a6ff; }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.8rem;
      margin-top: 0.4rem;
    }
    th, td {
      padding: 0.45rem 0.4rem;
      text-align: left;
      border-bottom: 1px solid #1f2937;
    }
    th { color: #94a3b8; }
    #map {
      height: 190px;
      background: #0b1220;
      border-radius: 8px;
      border: 1px solid #1f2937;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #6b7280;
      margin-bottom: 0.6rem;
      font-size: 0.85rem;
    }
    #map.leaflet-container { color: #e6edf3; }
    .map-legend {
      display: flex;
      gap: 0.6rem;
      font-size: 0.75rem;
      color: #9ca3af;
      margin-bottom: 0.4rem;
    }
    .legend-dot {
      width: 10px;
      height: 10px;
      border-radius: 999px;
      display: inline-block;
      margin-right: 0.3rem;
    }
    .chart-wrap {
      background: #0b1220;
      border: 1px solid #1f2937;
      border-radius: 8px;
      padding: 0.8rem;
    }
    .grid-2 {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1rem;
    }
    .timeline {
      max-height: 220px;
      overflow: auto;
      font-size: 0.82rem;
    }
    .timeline-item {
      border-left: 2px solid #374151;
      padding: 0.4rem 0.6rem;
      margin-bottom: 0.4rem;
      background: #0b1220;
      border-radius: 6px;
    }
    .timeline-item strong { color: #93c5fd; }
    .log-feed {
      background: #0b1220;
      border: 1px solid #1f2937;
      border-radius: 8px;
      padding: 0.6rem;
      max-height: 220px;
      overflow: auto;
      font-size: 0.78rem;
    }
    .log-line {
      border-bottom: 1px solid #1f2937;
      padding: 0.3rem 0;
    }
    .action-bar {
      display: flex;
      gap: 0.6rem;
      flex-wrap: wrap;
    }
    .btn {
      border: 1px solid #1f2937;
      background: #111827;
      color: #e5e7eb;
      padding: 0.4rem 0.8rem;
      border-radius: 6px;
      cursor: pointer;
      font-size: 0.8rem;
    }
    .btn.primary {
      background: #2563eb;
      border-color: #1d4ed8;
    }
    .btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }
    .token-box {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas,
        "Liberation Mono", monospace;
      font-size: 0.75rem;
      background: #0b1220;
      border: 1px solid #1f2937;
      padding: 0.6rem;
      border-radius: 6px;
      word-break: break-all;
      max-height: 120px;
      overflow: auto;
    }
    .full { grid-column: 1 / -1; }
    footer {
      padding: 0.8rem 2rem 1.5rem;
      color: #6b7280;
      font-size: 0.75rem;
    }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>ROS Cyber — Security Operations Center</h1>
      <p>Real-time fleet security posture, policy enforcement, and threat telemetry.</p>
    </div>
    <span class="badge" id="ws-status">Connecting...</span>
  </header>
  <main class="layout">
    <div class="panel">
      <h2>Fleet Overview</h2>
      <div class="stat-grid">
        <div class="stat">
          <div class="val" id="robot-count">-</div>
          <div class="lbl">Active Robots</div>
        </div>
        <div class="stat">
          <div class="val" id="alert-count">-</div>
          <div class="lbl">Open Alerts</div>
        </div>
        <div class="stat">
          <div class="val" id="scan-count">-</div>
          <div class="lbl">Scan Findings</div>
        </div>
      </div>
    </div>
    <div class="panel">
      <h2>Compliance & Controls</h2>
      <div class="pill-row">
        <span class="pill">Profile: <strong id="profile">hardened</strong></span>
        <span class="pill">Kill Switch: <strong id="kill">OFF</strong></span>
        <span class="pill">Last Scan: <strong id="last-scan">-</strong></span>
        <span class="pill">Uptime: <strong id="uptime">-</strong></span>
        <span class="pill">Server Time: <strong id="server-time">-</strong></span>
        <span class="pill">Role: <strong id="role">guest</strong></span>
      </div>
      <div class="action-bar" style="margin-top: 0.8rem;">
        <button class="btn primary" id="demo-seed-btn">Seed Demo Data</button>
        <button class="btn" id="export-alerts-btn">Export Alerts CSV</button>
        <button class="btn" id="export-audit-btn">Export Audit CSV</button>
        <button class="btn" id="export-alerts-json">Alerts JSON</button>
        <button class="btn" id="export-audit-json">Audit JSON</button>
      </div>
    </div>
    <div class="panel full">
      <h2>Live Alert Feed</h2>
      <div class="action-bar" style="margin-bottom: 0.6rem;">
        <label class="pill">
          Severity:
          <select id="alert-filter">
            <option value="all">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </label>
      </div>
      <div id="alerts"><div class="alert medium">Waiting for events...</div></div>
    </div>
    <div class="panel full">
      <h2>Alert Analytics</h2>
      <div class="grid-2">
        <div class="chart-wrap">
          <canvas id="alert-chart" height="120"></canvas>
        </div>
        <div class="chart-wrap">
          <canvas id="severity-chart" height="120"></canvas>
        </div>
      </div>
      <div class="pill-row" id="severity-counts" style="margin-top: 0.8rem;"></div>
    </div>
    <div class="panel">
      <h2>Fleet Map (GPS)</h2>
      <div id="map">Robot positions loading...</div>
      <div class="map-legend">
        <span><span class="legend-dot" style="background:#22c55e"></span>70%+</span>
        <span><span class="legend-dot" style="background:#fbbf24"></span>40-69%</span>
        <span><span class="legend-dot" style="background:#ef4444"></span>Below 40%</span>
      </div>
      <table id="fleet-table">
        <thead>
          <tr><th>Robot</th><th>Lat</th><th>Lon</th><th>Battery</th></tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
    <div class="panel">
      <h2>Recent Audit Log</h2>
      <div class="action-bar" style="margin-bottom: 0.4rem;">
        <input id="audit-filter" placeholder="Filter robot..." />
      </div>
      <table id="audit-table">
        <thead>
          <tr><th>Robot</th><th>Decision</th><th>Reason</th></tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
    <div class="panel full">
      <h2>Attack Replay Timeline</h2>
      <div class="timeline" id="timeline"></div>
    </div>
    <div class="panel full">
      <h2>Live Log Stream</h2>
      <div class="log-feed" id="log-feed">Waiting for logs...</div>
    </div>
    <div class="panel full">
      <h2>Operator Session</h2>
      <div class="action-bar">
        <button class="btn" id="login-operator">Login as Operator</button>
        <button class="btn" id="login-admin">Login as Admin</button>
        <button class="btn" id="clear-token">Clear Token</button>
        <button class="btn" id="copy-token">Copy Token</button>
      </div>
      <div class="pill-row" style="margin-top: 0.6rem;">
        <span class="pill">Expires: <strong id="token-exp">-</strong></span>
        <span class="pill">User: <strong id="token-user">-</strong></span>
      </div>
      <div class="token-box" id="token-box">No token stored.</div>
    </div>
  </main>
  <footer>ROS Cyber v0.1.0 • Built for cyber-physical security telemetry.</footer>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
  <script
    src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"
    integrity="sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo="
    crossorigin=""
  ></script>
  <script>
    const alertsEl = document.getElementById('alerts');
    const wsStatus = document.getElementById('ws-status');
    const tokenBox = document.getElementById('token-box');
    const timelineEl = document.getElementById('timeline');
    const filterSelect = document.getElementById('alert-filter');
    const auditFilter = document.getElementById('audit-filter');
    const logFeed = document.getElementById('log-feed');
    const severityCounts = document.getElementById('severity-counts');
    const tokenKey = 'roscyber_token';
    const mapEl = document.getElementById('map');
    let map;
    let markers = {};
    let alertChart;
    let severityChart;
    let currentFilter = 'all';
    let auditQuery = '';

    function initMap() {
      map = L.map(mapEl, { zoomControl: true }).setView([14.6, 120.98], 12);
      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        maxZoom: 19,
        attribution: '&copy; OpenStreetMap contributors'
      }).addTo(map);
    }

    function batteryColor(level) {
      if (level >= 70) return '#22c55e';
      if (level >= 40) return '#fbbf24';
      return '#ef4444';
    }

    function initCharts() {
      const alertCtx = document.getElementById('alert-chart').getContext('2d');
      const severityCtx = document.getElementById('severity-chart').getContext('2d');
      alertChart = new Chart(alertCtx, {
        type: 'line',
        data: {
          labels: [],
          datasets: [{
            label: 'Alerts (last 10)',
            data: [],
            borderColor: '#60a5fa',
            backgroundColor: 'rgba(96,165,250,0.2)',
            tension: 0.3
          }]
        },
        options: {
          responsive: true,
          scales: { y: { beginAtZero: true } }
        }
      });
      severityChart = new Chart(severityCtx, {
        type: 'bar',
        data: {
          labels: ['critical', 'high', 'medium', 'low'],
          datasets: [{
            label: 'By Severity',
            data: [0, 0, 0, 0],
            backgroundColor: ['#f87171', '#fb923c', '#fbbf24', '#60a5fa']
          }]
        },
        options: {
          responsive: true,
          scales: { y: { beginAtZero: true } }
        }
      });
    }

    function addAlert(a) {
      const div = document.createElement('div');
      div.className = 'alert ' + (a.severity || 'medium');
      const title = a.mitre || 'T0000';
      const desc = a.description || '';
      const ackButton = a.acknowledged
        ? '<span class="pill">ACK</span>'
        : `<button class="btn" data-ack="${a.id}">Acknowledge</button>`;
      div.innerHTML = (
        `<strong>[${title}] ${a.title}</strong>` +
        `<br/><small>${a.robot_id} — ${desc}</small><br/>` +
        `<div class="action-bar" style="margin-top:0.4rem;">${ackButton}</div>`
      );
      const ackEl = div.querySelector('[data-ack]');
      if (ackEl) {
        ackEl.onclick = () => ackAlert(a.id);
      }
      alertsEl.insertBefore(div, alertsEl.firstChild);
      if (alertsEl.children.length > 20) alertsEl.removeChild(alertsEl.lastChild);
    }

    function renderEmptyAlerts() {
      alertsEl.innerHTML = (
        '<div class="alert low">No alerts yet. Run a demo event to populate the feed.</div>'
      );
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
      const fleetRows = d.fleet.map((r) => (
        `<tr><td>${r.robot_id}</td><td>${r.latitude.toFixed(4)}</td>` +
        `<td>${r.longitude.toFixed(4)}</td><td>${r.battery_pct}%</td></tr>`
      ));
      tbody.innerHTML = fleetRows.join('');
      if (!map) {
        initMap();
      }
      if (d.fleet.length === 0) {
        mapEl.textContent = 'No robots';
      } else {
        d.fleet.forEach((r) => {
          const coords = [r.latitude, r.longitude];
          const color = batteryColor(r.battery_pct);
          if (!markers[r.robot_id]) {
            markers[r.robot_id] = L.circleMarker(coords, {
              radius: 7,
              color,
              fillColor: color,
              fillOpacity: 0.9
            }).addTo(map).bindPopup(`${r.robot_id} (${r.battery_pct}%)`);
          } else {
            markers[r.robot_id].setLatLng(coords);
            markers[r.robot_id].setStyle({ color, fillColor: color });
          }
        });
        const bounds = L.latLngBounds(
          d.fleet.map((r) => [r.latitude, r.longitude])
        );
        if (bounds.isValid()) {
          map.fitBounds(bounds, { padding: [20, 20] });
        }
      }
      const audit = document.querySelector('#audit-table tbody');
      const auditRows = d.audit
        .filter((a) => (
          auditQuery === '' || a.robot_id.toLowerCase().includes(auditQuery)
        ))
        .map((a) => (
          `<tr><td>${a.robot_id}</td><td>${a.decision}</td><td>${a.reason}</td></tr>`
        ));
      audit.innerHTML = auditRows.join('');
      if (d.recent_alerts.length) {
        d.recent_alerts.forEach(addAlert);
      } else {
        renderEmptyAlerts();
      }
      const uptimeEl = document.getElementById('uptime');
      const serverTimeEl = document.getElementById('server-time');
      if (uptimeEl) { uptimeEl.textContent = d.uptime_human; }
      if (serverTimeEl) { serverTimeEl.textContent = d.server_time; }
    }

    async function pollAlerts() {
      const r = await fetch('/api/v1/alerts?limit=10');
      const data = await r.json();
      if (Array.isArray(data) && data.length) {
        alertsEl.innerHTML = '';
        const filtered = data.filter((a) => (
          currentFilter === 'all' || a.severity === currentFilter
        ));
        filtered.forEach(addAlert);
        updateCharts(filtered);
        renderTimeline(filtered);
      } else {
        renderEmptyAlerts();
      }
    }

    async function ackAlert(id) {
      await fetch(`/api/v1/alerts/${id}/ack`, { method: 'POST' });
      pollAlerts();
    }

    function updateCharts(alerts) {
      const labels = alerts.map((a) => new Date(a.created_at).toLocaleTimeString());
      const values = alerts.map(() => 1);
      alertChart.data.labels = labels;
      alertChart.data.datasets[0].data = values;
      alertChart.update();
      const counts = { critical: 0, high: 0, medium: 0, low: 0 };
      alerts.forEach((a) => { counts[a.severity] = (counts[a.severity] || 0) + 1; });
      severityChart.data.datasets[0].data = [
        counts.critical || 0,
        counts.high || 0,
        counts.medium || 0,
        counts.low || 0
      ];
      severityChart.update();
      severityCounts.innerHTML = (
        `<span class="pill">Critical: <strong>${counts.critical || 0}</strong></span>` +
        `<span class="pill">High: <strong>${counts.high || 0}</strong></span>` +
        `<span class="pill">Medium: <strong>${counts.medium || 0}</strong></span>` +
        `<span class="pill">Low: <strong>${counts.low || 0}</strong></span>`
      );
    }

    function renderTimeline(alerts) {
      const items = alerts.map((a) => (
        `<div class="timeline-item"><strong>${a.severity.toUpperCase()}</strong> ` +
        `${a.title} — ${new Date(a.created_at).toLocaleString()}</div>`
      ));
      timelineEl.innerHTML = items.join('') || '<div class="timeline-item">No alerts yet.</div>';
    }

    function setToken(token) {
      if (token) {
        localStorage.setItem(tokenKey, token);
        tokenBox.textContent = token;
        const meta = decodeJwt(token);
        if (meta) {
          const exp = meta.exp ? new Date(meta.exp * 1000).toLocaleString() : '-';
          document.getElementById('token-exp').textContent = exp;
          document.getElementById('token-user').textContent = meta.sub || '-';
        }
        refreshRole(token);
      } else {
        localStorage.removeItem(tokenKey);
        tokenBox.textContent = 'No token stored.';
        document.getElementById('role').textContent = 'guest';
        document.getElementById('token-exp').textContent = '-';
        document.getElementById('token-user').textContent = '-';
      }
    }

    function decodeJwt(token) {
      try {
        const payload = token.split('.')[1];
        const decoded = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
        return JSON.parse(decoded);
      } catch (_) {
        return null;
      }
    }

    async function refreshRole(token) {
      try {
        const resp = await fetch('/api/v1/me', {
          headers: { Authorization: `Bearer ${token}` }
        });
        if (resp.ok) {
          const data = await resp.json();
          document.getElementById('role').textContent = data.role;
          setRoleControls(data.role);
        }
      } catch (_) {
        document.getElementById('role').textContent = 'guest';
        setRoleControls('guest');
      }
    }

    function setRoleControls(role) {
      const seedBtn = document.getElementById('demo-seed-btn');
      const exportAlertsBtn = document.getElementById('export-alerts-btn');
      const exportAuditBtn = document.getElementById('export-audit-btn');
      const exportAlertsJson = document.getElementById('export-alerts-json');
      const exportAuditJson = document.getElementById('export-audit-json');
      if (role === 'admin') {
        seedBtn.disabled = false;
        exportAlertsBtn.disabled = false;
        exportAuditBtn.disabled = false;
        exportAlertsJson.disabled = false;
        exportAuditJson.disabled = false;
      } else if (role === 'operator') {
        seedBtn.disabled = false;
        exportAlertsBtn.disabled = true;
        exportAuditBtn.disabled = true;
        exportAlertsJson.disabled = true;
        exportAuditJson.disabled = true;
      } else {
        seedBtn.disabled = true;
        exportAlertsBtn.disabled = true;
        exportAuditBtn.disabled = true;
        exportAlertsJson.disabled = true;
        exportAuditJson.disabled = true;
      }
    }

    async function login(username, password) {
      const resp = await fetch('http://localhost:8000/v1/auth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      const data = await resp.json();
      setToken(data.access_token);
    }

    function copyToken() {
      const token = localStorage.getItem(tokenKey) || '';
      if (token) {
        navigator.clipboard.writeText(token);
      }
    }

    async function seedDemo() {
      const token = localStorage.getItem(tokenKey);
      if (!token) {
        await login('operator', 'operator123!');
      }
      await fetch('/api/v1/demo/seed');
      await pollAlerts();
      await refreshStats();
    }

    async function exportCsv(path) {
      window.open(path, '_blank');
    }

    let ws;
    function initWebSocket() {
      ws = new WebSocket(`ws://${location.host}/ws/alerts`);
      ws.onopen = () => {
        wsStatus.textContent = 'Live';
        wsStatus.style.background = '#238636';
      };
      ws.onclose = () => {
        wsStatus.textContent = 'Polling';
        wsStatus.style.background = '#d29922';
      };
      ws.onmessage = (e) => { addAlert(JSON.parse(e.data)); };
    }

    function initStreams() {
      const alertStream = new EventSource('/api/v1/stream/alerts');
      alertStream.onmessage = (event) => {
        const data = JSON.parse(event.data);
        addAlert({
          severity: data.severity,
          title: data.title,
          description: data.reason || data.title,
          robot_id: data.robot_id,
          mitre: data.mitre || 'T0000'
        });
        pollAlerts();
      };
      const auditStream = new EventSource('/api/v1/stream/audit');
      auditStream.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (logFeed.textContent.includes('Waiting')) {
          logFeed.textContent = '';
        }
        const line = document.createElement('div');
        line.className = 'log-line';
        line.textContent = (
          `${new Date(data.created_at).toLocaleTimeString()} ` +
          `${data.robot_id} ${data.decision} ${data.reason}`
        );
        logFeed.insertBefore(line, logFeed.firstChild);
        if (logFeed.children.length > 20) {
          logFeed.removeChild(logFeed.lastChild);
        }
        refreshStats();
      };
    }

    initCharts();
    initWebSocket();
    initStreams();
    refreshStats();
    pollAlerts();
    setInterval(refreshStats, 5000);
    setInterval(pollAlerts, 5000);

    document.getElementById('login-operator').onclick = () => login('operator', 'operator123!');
    document.getElementById('login-admin').onclick = () => login('admin', 'admin123!');
    document.getElementById('clear-token').onclick = () => setToken('');
    document.getElementById('copy-token').onclick = copyToken;
    document.getElementById('demo-seed-btn').onclick = seedDemo;
    document.getElementById('export-alerts-btn').onclick = () => (
      exportCsv('/api/v1/report/alerts.csv')
    );
    document.getElementById('export-audit-btn').onclick = () => (
      exportCsv('/api/v1/report/audit.csv')
    );
    document.getElementById('export-alerts-json').onclick = () => (
      exportCsv('/api/v1/report/alerts.json')
    );
    document.getElementById('export-audit-json').onclick = () => (
      exportCsv('/api/v1/report/audit.json')
    );
    setRoleControls('guest');
    const existingToken = localStorage.getItem(tokenKey);
    if (existingToken) {
      setToken(existingToken);
    }
    filterSelect.onchange = (event) => {
      currentFilter = event.target.value;
      pollAlerts();
    };
    auditFilter.oninput = (event) => {
      auditQuery = event.target.value.toLowerCase();
      refreshStats();
    };
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


def format_uptime(seconds: float) -> str:
    seconds = max(int(seconds), 0)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, rem = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    if minutes or hours or days:
        parts.append(f"{minutes}m")
    parts.append(f"{rem}s")
    return " ".join(parts)


def csv_response(rows: list[dict[str, Any]], filename: str) -> Response:
    buffer = io.StringIO()
    if rows:
        writer = csv.DictWriter(buffer, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    else:
        buffer.write("")
    content = buffer.getvalue().encode("utf-8")
    return Response(
        content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="ROS Cyber Dashboard", version=__version__)

    @app.on_event("startup")
    async def startup() -> None:
        await init_db()
        asyncio.create_task(_alert_listener())

    async def _alert_listener() -> None:
        if settings.disable_redis:
            logger.info("redis_disabled_alert_listener")
            return
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
            open_alerts_query = (
                select(func.count())
                .select_from(SecurityAlert)
                .where(SecurityAlert.acknowledged.is_(False))
            )
            open_alerts = (await session.execute(open_alerts_query)).scalar() or 0
            recent_query = select(SecurityAlert).order_by(desc(SecurityAlert.id)).limit(10)
            recent = (await session.execute(recent_query)).scalars().all()
            audit_query = select(CommandAuditLog).order_by(desc(CommandAuditLog.id)).limit(10)
            audit = (await session.execute(audit_query)).scalars().all()
            last_scan = (
                await session.execute(select(ScanReport).order_by(desc(ScanReport.id)).limit(1))
            ).scalar_one_or_none()
        server_time = datetime.now(timezone.utc)
        uptime_seconds = (server_time - START_TIME).total_seconds()
        return {
            "active_robots": len(robots),
            "open_alerts": open_alerts,
            "scan_findings": last_scan.findings_count if last_scan else 0,
            "profile": settings.profile,
            "kill_switch": settings.kill_switch_active,
            "last_scan": last_scan.created_at.isoformat() if last_scan else None,
            "server_time": server_time.isoformat(timespec="seconds"),
            "uptime_seconds": int(uptime_seconds),
            "uptime_human": format_uptime(uptime_seconds),
            "redis_enabled": not settings.disable_redis,
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
            "audit": [
                {"robot_id": a.robot_id, "decision": a.decision, "reason": a.reason}
                for a in audit
            ],
        }

    @app.get("/api/v1/alerts")
    async def alerts(limit: int = 20) -> list[dict[str, Any]]:
        factory = get_session_factory()
        async with factory() as session:
            query = select(SecurityAlert).order_by(desc(SecurityAlert.id)).limit(limit)
            rows = (await session.execute(query)).scalars().all()
        return [
            {
                "id": a.id,
                "severity": a.severity,
                "title": a.title,
                "description": a.description,
                "robot_id": a.robot_id,
                "mitre": a.mitre_technique,
                "acknowledged": a.acknowledged,
                "created_at": a.created_at.isoformat(),
            }
            for a in rows
        ]

    @app.post("/api/v1/alerts/{alert_id}/ack")
    async def ack_alert(alert_id: int) -> dict[str, str]:
        factory = get_session_factory()
        async with factory() as session:
            alert = await session.get(SecurityAlert, alert_id)
            if alert:
                alert.acknowledged = True
                await session.commit()
        return {"status": "acknowledged"}

    @app.get("/api/v1/audit")
    async def audit(limit: int = 20) -> list[dict[str, Any]]:
        factory = get_session_factory()
        async with factory() as session:
            query = select(CommandAuditLog).order_by(desc(CommandAuditLog.id)).limit(limit)
            rows = (await session.execute(query)).scalars().all()
        return [
            {
                "robot_id": a.robot_id,
                "decision": a.decision,
                "reason": a.reason,
                "created_at": a.created_at.isoformat(),
            }
            for a in rows
        ]

    @app.get("/api/v1/fleet")
    async def fleet() -> list[dict[str, Any]]:
        factory = get_session_factory()
        async with factory() as session:
            query = (
                select(RobotTelemetry)
                .distinct(RobotTelemetry.robot_id)
                .order_by(RobotTelemetry.robot_id, RobotTelemetry.id.desc())
            )
            rows = (await session.execute(query)).scalars().all()
        return [
            {
                "robot_id": r.robot_id,
                "latitude": r.latitude,
                "longitude": r.longitude,
                "battery_pct": r.battery_pct,
                "recorded_at": r.recorded_at.isoformat(),
            }
            for r in rows
        ]

    @app.get("/api/v1/me")
    async def me(user: User = Depends(get_current_user)) -> dict[str, str]:
        return {"username": user.username, "role": user.role.value}

    @app.get("/api/v1/report/alerts.csv")
    async def alerts_csv() -> Response:
        factory = get_session_factory()
        async with factory() as session:
            query = select(SecurityAlert).order_by(desc(SecurityAlert.id)).limit(200)
            rows = (await session.execute(query)).scalars().all()
        payload = [
            {
                "id": a.id,
                "severity": a.severity,
                "title": a.title,
                "robot_id": a.robot_id,
                "mitre": a.mitre_technique,
                "created_at": a.created_at.isoformat(),
            }
            for a in rows
        ]
        return csv_response(payload, "roscyber_alerts.csv")

    @app.get("/api/v1/report/alerts.json")
    async def alerts_json() -> list[dict[str, Any]]:
        factory = get_session_factory()
        async with factory() as session:
            query = select(SecurityAlert).order_by(desc(SecurityAlert.id)).limit(200)
            rows = (await session.execute(query)).scalars().all()
        return [
            {
                "id": a.id,
                "severity": a.severity,
                "title": a.title,
                "robot_id": a.robot_id,
                "mitre": a.mitre_technique,
                "created_at": a.created_at.isoformat(),
            }
            for a in rows
        ]

    @app.get("/api/v1/report/audit.csv")
    async def audit_csv() -> Response:
        factory = get_session_factory()
        async with factory() as session:
            query = select(CommandAuditLog).order_by(desc(CommandAuditLog.id)).limit(200)
            rows = (await session.execute(query)).scalars().all()
        payload = [
            {
                "id": a.id,
                "robot_id": a.robot_id,
                "decision": a.decision,
                "reason": a.reason,
                "created_at": a.created_at.isoformat(),
            }
            for a in rows
        ]
        return csv_response(payload, "roscyber_audit.csv")

    @app.get("/api/v1/report/audit.json")
    async def audit_json() -> list[dict[str, Any]]:
        factory = get_session_factory()
        async with factory() as session:
            query = select(CommandAuditLog).order_by(desc(CommandAuditLog.id)).limit(200)
            rows = (await session.execute(query)).scalars().all()
        return [
            {
                "id": a.id,
                "robot_id": a.robot_id,
                "decision": a.decision,
                "reason": a.reason,
                "created_at": a.created_at.isoformat(),
            }
            for a in rows
        ]

    @app.get("/api/v1/demo/seed")
    async def demo_seed(request: Request) -> dict[str, str]:
        factory = get_session_factory()
        now = datetime.now(timezone.utc)
        async with factory() as session:
            for i in range(5):
                session.add(
                    RobotTelemetry(
                        robot_id="robot-alpha",
                        latitude=14.6 + (i * 0.0005),
                        longitude=120.98 + (i * 0.0005),
                        battery_pct=92,
                        motor_rpm=650,
                        firmware_version="1.0.0",
                    )
                )
            session.add(
                CommandAuditLog(
                    robot_id="robot-alpha",
                    user_id="operator",
                    command_type="cmd_vel",
                    payload="{}",
                    decision="allow",
                    reason="demo_allow",
                    correlation_id="demo",
                )
            )
            session.add(
                CommandAuditLog(
                    robot_id="robot-alpha",
                    user_id="operator",
                    command_type="cmd_vel",
                    payload="{}",
                    decision="deny",
                    reason="demo_deny",
                    correlation_id="demo",
                )
            )
            session.add(
                SecurityAlert(
                    robot_id="robot-alpha",
                    severity="high",
                    title="Policy violation",
                    description="Demo policy denial",
                    mitre_technique="T0855",
                    iec_control="SR 3.3",
                    raw_event=json.dumps({"source": "demo"}),
                    created_at=now,
                )
            )
            await session.commit()
        return {"status": "seeded"}

    async def _stream_events(query_fn, key: str) -> Any:
        last_id = 0
        while True:
            factory = get_session_factory()
            async with factory() as session:
                rows = (await session.execute(query_fn(last_id))).scalars().all()
            for row in rows:
                last_id = max(last_id, row.id)
                payload = {
                    "type": key,
                    "id": row.id,
                    "robot_id": getattr(row, "robot_id", ""),
                    "title": getattr(row, "title", ""),
                    "severity": getattr(row, "severity", ""),
                    "decision": getattr(row, "decision", ""),
                    "reason": getattr(row, "reason", ""),
                    "created_at": row.created_at.isoformat(),
                }
                yield f"data: {json.dumps(payload)}\n\n"
            await asyncio.sleep(2)

    @app.get("/api/v1/stream/alerts")
    async def stream_alerts() -> StreamingResponse:
        def query(last_id: int):
            return (
                select(SecurityAlert)
                .where(SecurityAlert.id > last_id)
                .order_by(SecurityAlert.id.asc())
            )

        return StreamingResponse(_stream_events(query, "alert"), media_type="text/event-stream")

    @app.get("/api/v1/stream/audit")
    async def stream_audit() -> StreamingResponse:
        def query(last_id: int):
            return (
                select(CommandAuditLog)
                .where(CommandAuditLog.id > last_id)
                .order_by(CommandAuditLog.id.asc())
            )

        return StreamingResponse(_stream_events(query, "audit"), media_type="text/event-stream")

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
