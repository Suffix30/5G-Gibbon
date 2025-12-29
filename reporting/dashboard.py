#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import logging
import threading
import time
from datetime import datetime
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field, asdict
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import sqlite3

logger = logging.getLogger(__name__)

@dataclass
class DashboardMetric:
    name: str
    value: float
    unit: str = ""
    trend: str = "stable"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class AttackEvent:
    event_id: str
    attack_type: str
    target: str
    status: str
    timestamp: str
    details: Dict[str, Any] = field(default_factory=dict)

class DashboardData:
    def __init__(self, db_path: str = "reports/dashboard.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        
        self.metrics: Dict[str, DashboardMetric] = {}
        self.events: List[AttackEvent] = []
        self.attack_stats = {
            "total": 0,
            "successful": 0,
            "failed": 0,
            "in_progress": 0
        }
    
    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                value REAL NOT NULL,
                unit TEXT,
                trend TEXT,
                timestamp TEXT NOT NULL
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                details TEXT
            )
        """)
        
        conn.commit()
        conn.close()
    
    def add_metric(self, metric: DashboardMetric):
        self.metrics[metric.name] = metric
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO metrics (name, value, unit, trend, timestamp) VALUES (?, ?, ?, ?, ?)",
            (metric.name, metric.value, metric.unit, metric.trend, metric.timestamp)
        )
        conn.commit()
        conn.close()
    
    def add_event(self, event: AttackEvent):
        self.events.insert(0, event)
        if len(self.events) > 100:
            self.events = self.events[:100]
        
        self.attack_stats["total"] += 1
        if event.status == "success":
            self.attack_stats["successful"] += 1
        elif event.status == "failed":
            self.attack_stats["failed"] += 1
        elif event.status == "running":
            self.attack_stats["in_progress"] += 1
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO events (event_id, attack_type, target, status, timestamp, details) VALUES (?, ?, ?, ?, ?, ?)",
            (event.event_id, event.attack_type, event.target, event.status, event.timestamp, json.dumps(event.details))
        )
        conn.commit()
        conn.close()
    
    def get_recent_metrics(self, name: str, limit: int = 100) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT value, timestamp FROM metrics WHERE name = ? ORDER BY id DESC LIMIT ?",
            (name, limit)
        )
        rows = cursor.fetchall()
        conn.close()
        
        return [{"value": r[0], "timestamp": r[1]} for r in reversed(rows)]
    
    def get_api_data(self) -> Dict[str, Any]:
        return {
            "metrics": {k: asdict(v) for k, v in self.metrics.items()},
            "events": [asdict(e) for e in self.events[:20]],
            "stats": self.attack_stats,
            "timestamp": datetime.now().isoformat()
        }

class DashboardHandler(BaseHTTPRequestHandler):
    dashboard_data: Optional[DashboardData] = None
    
    def log_message(self, format: str, *args):
        pass
    
    def do_GET(self):
        parsed = urlparse(self.path)
        
        if parsed.path == "/" or parsed.path == "/index.html":
            self._serve_dashboard()
        elif parsed.path == "/api/data":
            self._serve_api_data()
        elif parsed.path == "/api/metrics":
            self._serve_metrics()
        elif parsed.path == "/api/events":
            self._serve_events()
        else:
            self.send_error(404)
    
    def _serve_dashboard(self):
        html = self._get_dashboard_html()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(html.encode())
    
    def _serve_api_data(self):
        if self.dashboard_data:
            data = self.dashboard_data.get_api_data()
        else:
            data = {}
        
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def _serve_metrics(self):
        metrics = {}
        if self.dashboard_data:
            for name in self.dashboard_data.metrics:
                metrics[name] = self.dashboard_data.get_recent_metrics(name)
        
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(metrics).encode())
    
    def _serve_events(self):
        events = []
        if self.dashboard_data:
            events = [asdict(e) for e in self.dashboard_data.events]
        
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(events).encode())
    
    def _get_dashboard_html(self) -> str:
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>5G-Gibbon Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg-primary: #0a0a0f;
            --bg-secondary: #12121a;
            --bg-tertiary: #1a1a25;
            --text-primary: #e0e0e8;
            --text-secondary: #a0a0b0;
            --accent-cyan: #00d4ff;
            --accent-magenta: #ff00ff;
            --accent-green: #00ff88;
            --accent-red: #ff0040;
            --accent-yellow: #ffaa00;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'JetBrains Mono', 'Consolas', monospace;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
        }
        
        .header {
            background: linear-gradient(135deg, var(--bg-secondary), var(--bg-tertiary));
            padding: 1rem 2rem;
            border-bottom: 2px solid var(--accent-cyan);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .header h1 {
            background: linear-gradient(90deg, var(--accent-cyan), var(--accent-magenta));
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
            font-size: 1.5rem;
        }
        
        .status-indicator {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .status-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: var(--accent-green);
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .container {
            padding: 1rem;
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            grid-template-rows: auto auto 1fr;
            gap: 1rem;
            height: calc(100vh - 60px);
        }
        
        .stat-card {
            background: var(--bg-secondary);
            border-radius: 8px;
            padding: 1rem;
            border-left: 4px solid var(--accent-cyan);
        }
        
        .stat-card.success { border-left-color: var(--accent-green); }
        .stat-card.failed { border-left-color: var(--accent-red); }
        .stat-card.progress { border-left-color: var(--accent-yellow); }
        
        .stat-value {
            font-size: 2rem;
            font-weight: bold;
            color: var(--accent-cyan);
        }
        
        .stat-card.success .stat-value { color: var(--accent-green); }
        .stat-card.failed .stat-value { color: var(--accent-red); }
        .stat-card.progress .stat-value { color: var(--accent-yellow); }
        
        .stat-label {
            color: var(--text-secondary);
            font-size: 0.85rem;
        }
        
        .panel {
            background: var(--bg-secondary);
            border-radius: 8px;
            padding: 1rem;
            overflow: hidden;
        }
        
        .panel h2 {
            color: var(--accent-cyan);
            font-size: 1rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--bg-tertiary);
        }
        
        .chart-panel {
            grid-column: span 2;
        }
        
        .events-panel {
            grid-column: span 2;
            grid-row: span 2;
        }
        
        .metrics-panel {
            grid-column: span 2;
        }
        
        .event-list {
            list-style: none;
            max-height: calc(100% - 40px);
            overflow-y: auto;
        }
        
        .event-item {
            padding: 0.75rem;
            border-radius: 4px;
            background: var(--bg-tertiary);
            margin-bottom: 0.5rem;
            border-left: 3px solid var(--accent-cyan);
        }
        
        .event-item.success { border-left-color: var(--accent-green); }
        .event-item.failed { border-left-color: var(--accent-red); }
        .event-item.running { border-left-color: var(--accent-yellow); }
        
        .event-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 0.25rem;
        }
        
        .event-type {
            font-weight: bold;
        }
        
        .event-status {
            font-size: 0.75rem;
            padding: 0.15rem 0.5rem;
            border-radius: 3px;
            background: var(--bg-primary);
        }
        
        .event-status.success { color: var(--accent-green); }
        .event-status.failed { color: var(--accent-red); }
        .event-status.running { color: var(--accent-yellow); }
        
        .event-target {
            color: var(--text-secondary);
            font-size: 0.85rem;
        }
        
        .event-time {
            color: var(--text-secondary);
            font-size: 0.75rem;
        }
        
        .metric-row {
            display: flex;
            justify-content: space-between;
            padding: 0.5rem 0;
            border-bottom: 1px solid var(--bg-tertiary);
        }
        
        .metric-name { color: var(--text-secondary); }
        .metric-value { font-weight: bold; }
        
        #attackChart, #timelineChart {
            max-height: 200px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>5G-Gibbon Security Dashboard</h1>
        <div class="status-indicator">
            <div class="status-dot"></div>
            <span id="lastUpdate">Updating...</span>
        </div>
    </div>
    
    <div class="container">
        <div class="stat-card">
            <div class="stat-value" id="totalAttacks">0</div>
            <div class="stat-label">Total Attacks</div>
        </div>
        <div class="stat-card success">
            <div class="stat-value" id="successfulAttacks">0</div>
            <div class="stat-label">Successful</div>
        </div>
        <div class="stat-card failed">
            <div class="stat-value" id="failedAttacks">0</div>
            <div class="stat-label">Failed</div>
        </div>
        <div class="stat-card progress">
            <div class="stat-value" id="inProgress">0</div>
            <div class="stat-label">In Progress</div>
        </div>
        
        <div class="panel chart-panel">
            <h2>Attack Success Rate</h2>
            <canvas id="attackChart"></canvas>
        </div>
        
        <div class="panel events-panel">
            <h2>Recent Events</h2>
            <ul class="event-list" id="eventList"></ul>
        </div>
        
        <div class="panel metrics-panel">
            <h2>Performance Metrics</h2>
            <div id="metricsList"></div>
        </div>
    </div>
    
    <script>
        let attackChart = null;
        
        function initCharts() {
            const ctx = document.getElementById('attackChart').getContext('2d');
            attackChart = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: ['Successful', 'Failed', 'In Progress'],
                    datasets: [{
                        data: [0, 0, 0],
                        backgroundColor: ['#00ff88', '#ff0040', '#ffaa00'],
                        borderColor: '#1a1a25',
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: { color: '#e0e0e8', font: { family: 'monospace' } }
                        }
                    }
                }
            });
        }
        
        function updateDashboard(data) {
            document.getElementById('totalAttacks').textContent = data.stats.total;
            document.getElementById('successfulAttacks').textContent = data.stats.successful;
            document.getElementById('failedAttacks').textContent = data.stats.failed;
            document.getElementById('inProgress').textContent = data.stats.in_progress;
            
            if (attackChart) {
                attackChart.data.datasets[0].data = [
                    data.stats.successful,
                    data.stats.failed,
                    data.stats.in_progress
                ];
                attackChart.update();
            }
            
            const eventList = document.getElementById('eventList');
            eventList.innerHTML = data.events.map(e => `
                <li class="event-item ${e.status}">
                    <div class="event-header">
                        <span class="event-type">${e.attack_type}</span>
                        <span class="event-status ${e.status}">${e.status.toUpperCase()}</span>
                    </div>
                    <div class="event-target">${e.target}</div>
                    <div class="event-time">${new Date(e.timestamp).toLocaleString()}</div>
                </li>
            `).join('');
            
            const metricsList = document.getElementById('metricsList');
            metricsList.innerHTML = Object.entries(data.metrics).map(([name, m]) => `
                <div class="metric-row">
                    <span class="metric-name">${name}</span>
                    <span class="metric-value">${m.value.toFixed(2)} ${m.unit}</span>
                </div>
            `).join('');
            
            document.getElementById('lastUpdate').textContent = 
                'Updated: ' + new Date().toLocaleTimeString();
        }
        
        async function fetchData() {
            try {
                const response = await fetch('/api/data');
                const data = await response.json();
                updateDashboard(data);
            } catch (error) {
                console.error('Failed to fetch data:', error);
            }
        }
        
        initCharts();
        fetchData();
        setInterval(fetchData, 2000);
    </script>
</body>
</html>"""

class DashboardServer:
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8080,
        data: Optional[DashboardData] = None
    ):
        self.host = host
        self.port = port
        self.data = data or DashboardData()
        self.server: Optional[HTTPServer] = None
        self.thread: Optional[threading.Thread] = None
    
    def start(self, blocking: bool = False):
        DashboardHandler.dashboard_data = self.data
        
        self.server = HTTPServer((self.host, self.port), DashboardHandler)
        
        logger.info(f"Dashboard server starting on http://{self.host}:{self.port}")
        
        if blocking:
            self.server.serve_forever()
        else:
            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()
    
    def stop(self):
        if self.server:
            self.server.shutdown()
            logger.info("Dashboard server stopped")
    
    def add_metric(self, name: str, value: float, unit: str = "", trend: str = "stable"):
        self.data.add_metric(DashboardMetric(name, value, unit, trend))
    
    def add_event(
        self,
        attack_type: str,
        target: str,
        status: str,
        details: Optional[Dict] = None
    ):
        import uuid
        event = AttackEvent(
            event_id=str(uuid.uuid4())[:8],
            attack_type=attack_type,
            target=target,
            status=status,
            timestamp=datetime.now().isoformat(),
            details=details or {}
        )
        self.data.add_event(event)

def start_dashboard(port: int = 8080, blocking: bool = True) -> DashboardServer:
    server = DashboardServer(port=port)
    server.start(blocking=blocking)
    return server

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="5G-Gibbon Dashboard Server")
    parser.add_argument("--port", "-p", type=int, default=8080)
    parser.add_argument("--demo", action="store_true", help="Run with demo data")
    
    args = parser.parse_args()
    
    logging.basicConfig(level=logging.INFO)
    
    server = DashboardServer(port=args.port)
    server.start(blocking=False)
    
    print(f"Dashboard running at http://localhost:{args.port}")
    
    if args.demo:
        import random
        
        attack_types = ["TEID Enumeration", "PFCP Session Hijack", "GTP-U DoS", "Key Extraction", "Billing Fraud"]
        targets = ["10.0.0.10:2152", "10.0.0.20:8805", "10.0.0.30:38412"]
        statuses = ["success", "failed", "running"]
        
        try:
            while True:
                server.add_metric("packets_per_second", random.uniform(100, 5000), "pps")
                server.add_metric("response_time", random.uniform(1, 100), "ms")
                server.add_metric("success_rate", random.uniform(50, 100), "%")
                
                if random.random() < 0.3:
                    server.add_event(
                        random.choice(attack_types),
                        random.choice(targets),
                        random.choice(statuses),
                        {"teids_found": random.randint(0, 100)}
                    )
                
                time.sleep(2)
        except KeyboardInterrupt:
            print("\nShutting down...")
            server.stop()
    else:
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down...")
            server.stop()

