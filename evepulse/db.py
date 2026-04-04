"""
SQLite Database Layer for EvePulse
Stores captured network events and generated behavioral alerts.
Provides querying for statistics, historical reports, and forensics.
"""

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


class EventDatabase:
    """Manages local SQLite database for Suricata events and detection alerts."""

    def __init__(self, db_path: str = "data/evepulse.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    event_type TEXT,
                    src_ip TEXT,
                    dest_ip TEXT,
                    domain TEXT,
                    uri TEXT,
                    raw_json TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    src_ip TEXT,
                    domain TEXT,
                    severity TEXT,
                    score INTEGER,
                    reasons TEXT,
                    details TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_src ON events(src_ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity)")

    def insert_event(self, event_type: str, src_ip: str, domain: str = "", uri: str = "", dest_ip: str = "", raw: Optional[dict] = None) -> int:
        now = time.time()
        raw_str = json.dumps(raw) if raw else ""
        with self._get_conn() as conn:
            cur = conn.execute(
                """
                INSERT INTO events (timestamp, event_type, src_ip, dest_ip, domain, uri, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (now, event_type, src_ip, dest_ip, domain, uri, raw_str),
            )
            return cur.lastrowid

    def insert_alert(self, src_ip: str, domain: str, severity: str, score: int, reasons: str, details: str = "") -> int:
        now = time.time()
        with self._get_conn() as conn:
            cur = conn.execute(
                """
                INSERT INTO alerts (timestamp, src_ip, domain, severity, score, reasons, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (now, src_ip, domain, severity, score, reasons, details),
            )
            return cur.lastrowid

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute(
                """
                SELECT id, timestamp, src_ip, domain, severity, score, reasons, details
                FROM alerts ORDER BY id DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute(
                """
                SELECT id, timestamp, event_type, src_ip, dest_ip, domain, uri
                FROM events ORDER BY id DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_statistics(self) -> Dict[str, Any]:
        with self._get_conn() as conn:
            total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            high_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'HIGH'").fetchone()[0]
            medium_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'MEDIUM'").fetchone()[0]
            low_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'LOW'").fetchone()[0]

            top_sources = conn.execute(
                """
                SELECT src_ip, COUNT(*) as count FROM alerts
                GROUP BY src_ip ORDER BY count DESC LIMIT 5
                """
            ).fetchall()

            top_domains = conn.execute(
                """
                SELECT domain, COUNT(*) as count FROM events
                WHERE domain != '' GROUP BY domain ORDER BY count DESC LIMIT 5
                """
            ).fetchall()

            return {
                "total_events": total_events,
                "total_alerts": total_alerts,
                "severity_counts": {
                    "HIGH": high_alerts,
                    "MEDIUM": medium_alerts,
                    "LOW": low_alerts,
                },
                "top_sources": [dict(r) for r in top_sources],
                "top_domains": [dict(r) for r in top_domains],
            }
