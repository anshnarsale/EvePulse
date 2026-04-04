"""
Embedded Web Dashboard & REST API for EvePulse
Zero-dependency Python HTTP server providing a modern SOC terminal web UI
and JSON API endpoints for event querying and incident export.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional
from urllib.parse import parse_qs, urlparse

from evepulse.db import EventDatabase
from evepulse.export import export_to_cef, export_to_csv, export_to_json

HTML_DASHBOARD = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>EvePulse — Defensive Network Monitor</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #090d16;
      --card-bg: rgba(18, 24, 38, 0.7);
      --border: rgba(255, 255, 255, 0.08);
      --accent-cyan: #06b6d4;
      --accent-green: #10b981;
      --accent-yellow: #f59e0b;
      --accent-red: #ef4444;
      --text: #f1f5f9;
      --text-muted: #94a3b8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: 'Inter', sans-serif;
      min-height: 100vh;
      padding: 24px;
      background-image: radial-gradient(circle at 15% 15%, rgba(6, 182, 212, 0.08) 0%, transparent 40%),
                        radial-gradient(circle at 85% 85%, rgba(239, 68, 68, 0.05) 0%, transparent 40%);
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--border);
    }
    .logo-group { display: flex; align-items: center; gap: 12px; }
    .pulse-dot {
      width: 12px; height: 12px;
      background: var(--accent-green);
      border-radius: 50%;
      box-shadow: 0 0 12px var(--accent-green);
      animation: pulse 2s infinite;
    }
    @keyframes pulse { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.4; transform: scale(0.9); } }
    h1 { font-size: 1.5rem; font-weight: 700; letter-spacing: -0.02em; }
    .status-badge {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.75rem;
      background: rgba(16, 185, 129, 0.15);
      color: var(--accent-green);
      padding: 4px 10px;
      border-radius: 999px;
      border: 1px solid rgba(16, 185, 129, 0.3);
    }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .card {
      background: var(--card-bg);
      backdrop-filter: blur(12px);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 18px;
    }
    .card-title { font-size: 0.8rem; font-weight: 600; text-transform: uppercase; color: var(--text-muted); margin-bottom: 8px; }
    .card-val { font-size: 1.75rem; font-weight: 700; font-family: 'JetBrains Mono', monospace; }
    .high-val { color: var(--accent-red); }
    .med-val { color: var(--accent-yellow); }
    .low-val { color: var(--accent-green); }
    .actions { display: flex; gap: 10px; margin-bottom: 20px; }
    .btn {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 8px 14px;
      border-radius: 8px;
      font-size: 0.85rem;
      cursor: pointer;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      transition: all 0.2s;
    }
    .btn:hover { background: rgba(255, 255, 255, 0.1); border-color: var(--accent-cyan); color: var(--accent-cyan); }
    .table-container {
      background: var(--card-bg);
      backdrop-filter: blur(12px);
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow: hidden;
    }
    .table-header { padding: 16px 20px; font-weight: 600; font-size: 1rem; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
    table { width: 100%; border-collapse: collapse; font-size: 0.85rem; font-family: 'JetBrains Mono', monospace; }
    th { text-align: left; padding: 12px 20px; color: var(--text-muted); font-size: 0.75rem; font-weight: 600; border-bottom: 1px solid var(--border); }
    td { padding: 12px 20px; border-bottom: 1px solid var(--border); }
    tr:hover { background: rgba(255, 255, 255, 0.02); }
    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 0.7rem;
      font-weight: 700;
    }
    .badge-HIGH { background: rgba(239, 68, 68, 0.2); color: var(--accent-red); border: 1px solid rgba(239, 68, 68, 0.3); }
    .badge-MEDIUM { background: rgba(245, 158, 11, 0.2); color: var(--accent-yellow); border: 1px solid rgba(245, 158, 11, 0.3); }
    .badge-LOW { background: rgba(16, 185, 129, 0.2); color: var(--accent-green); border: 1px solid rgba(16, 185, 129, 0.3); }
  </style>
</head>
<body>
  <div class="header">
    <div class="logo-group">
      <div class="pulse-dot"></div>
      <h1>EvePulse <span style="font-weight:400; font-size: 0.9rem; color:var(--text-muted);">Defensive Monitor v0.3.0</span></h1>
    </div>
    <div class="status-badge">SURICATA ACTIVE</div>
  </div>

  <div class="grid">
    <div class="card">
      <div class="card-title">Total Network Events</div>
      <div class="card-val" id="total-events">0</div>
    </div>
    <div class="card">
      <div class="card-title">High Threats</div>
      <div class="card-val high-val" id="high-threats">0</div>
    </div>
    <div class="card">
      <div class="card-title">Medium Threats</div>
      <div class="card-val med-val" id="med-threats">0</div>
    </div>
    <div class="card">
      <div class="card-title">Low / Info Alerts</div>
      <div class="card-val low-val" id="low-threats">0</div>
    </div>
  </div>

  <div class="actions">
    <a href="/api/export?format=json" class="btn" download="evepulse-alerts.json">Export JSON</a>
    <a href="/api/export?format=csv" class="btn" download="evepulse-alerts.csv">Export CSV</a>
    <a href="/api/export?format=cef" class="btn" download="evepulse-alerts.cef">Export CEF (SIEM)</a>
  </div>

  <div class="table-container">
    <div class="table-header">
      <span>Live Security Alerts Feed</span>
      <span style="font-size:0.8rem; color:var(--text-muted);" id="refresh-indicator">Auto-refresh: 3s</span>
    </div>
    <table>
      <thead>
        <tr>
          <th>TIMESTAMP</th>
          <th>SEVERITY</th>
          <th>SOURCE IP</th>
          <th>TARGET DOMAIN</th>
          <th>SCORE</th>
          <th>INDICATORS</th>
        </tr>
      </thead>
      <tbody id="alerts-tbody">
        <tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:24px;">Listening for Suricata EVE logs...</td></tr>
      </tbody>
    </table>
  </div>

  <script>
    async function loadData() {
      try {
        const statsRes = await fetch('/api/stats');
        const stats = await statsRes.json();
        document.getElementById('total-events').innerText = stats.total_events || 0;
        document.getElementById('high-threats').innerText = stats.severity_counts?.HIGH || 0;
        document.getElementById('med-threats').innerText = stats.severity_counts?.MEDIUM || 0;
        document.getElementById('low-threats').innerText = stats.severity_counts?.LOW || 0;

        const alertsRes = await fetch('/api/alerts');
        const alerts = await alertsRes.json();
        const tbody = document.getElementById('alerts-tbody');
        if (alerts.length > 0) {
          tbody.innerHTML = alerts.map(a => {
            const timeStr = new Date(a.timestamp * 1000).toLocaleTimeString();
            return `
              <tr>
                <td>${timeStr}</td>
                <td><span class="badge badge-${a.severity}">${a.severity}</span></td>
                <td><code>${a.src_ip}</code></td>
                <td>${a.domain || '-'}</td>
                <td><b>${a.score}</b></td>
                <td>${a.reasons || ''}</td>
              </tr>
            `;
          }).join('');
        }
      } catch (err) {
        console.error(err);
      }
    }
    loadData();
    setInterval(loadData, 3000);
  </script>
</body>
</html>
"""


class DashboardHandler(BaseHTTPRequestHandler):
    db: Optional[EventDatabase] = None

    def log_message(self, format, *args):
        # Silence console log spam for cleaner terminal output
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/" or path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_DASHBOARD.encode("utf-8"))
            return

        if path == "/api/stats":
            stats = self.db.get_statistics() if self.db else {}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(stats).encode("utf-8"))
            return

        if path == "/api/alerts":
            alerts = self.db.get_recent_alerts(limit=50) if self.db else []
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(alerts).encode("utf-8"))
            return

        if path == "/api/events":
            events = self.db.get_recent_events(limit=50) if self.db else []
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(events).encode("utf-8"))
            return

        if path == "/api/export":
            fmt = query.get("format", ["json"])[0].lower()
            alerts = self.db.get_recent_alerts(limit=500) if self.db else []
            if fmt == "csv":
                content = export_to_csv(alerts)
                ctype = "text/csv"
                fname = "evepulse-alerts.csv"
            elif fmt == "cef":
                content = export_to_cef(alerts)
                ctype = "text/plain"
                fname = "evepulse-alerts.cef"
            else:
                content = export_to_json(alerts)
                ctype = "application/json"
                fname = "evepulse-alerts.json"

            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Disposition", f"attachment; filename=\"{fname}\"")
            self.end_headers()
            self.wfile.write(content.encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()


def start_web_server(db: EventDatabase, host: str = "127.0.0.1", port: int = 8088) -> HTTPServer:
    """Starts the embedded dashboard in a non-blocking background daemon thread."""
    handler = DashboardHandler
    handler.db = db
    server = HTTPServer((host, port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server
