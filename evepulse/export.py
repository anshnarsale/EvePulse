"""
Export Utility for EvePulse
Supports exporting alerts and security events to JSON, CSV, CEF, and Markdown reports.
"""

import csv
import io
import json
import time
from typing import Any, Dict, List


def export_to_json(alerts: List[Dict[str, Any]], indent: int = 2) -> str:
    """Exports a list of alerts to structured JSON."""
    return json.dumps({"alerts": alerts, "count": len(alerts), "exported_at": time.time()}, indent=indent)


def export_to_csv(alerts: List[Dict[str, Any]]) -> str:
    """Exports a list of alerts to RFC 4180 compliant CSV."""
    output = io.StringIO()
    fields = ["id", "timestamp", "severity", "score", "src_ip", "domain", "reasons", "details"]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for alert in alerts:
        writer.writerow(alert)
    return output.getvalue()


def export_to_cef(alerts: List[Dict[str, Any]], device_vendor: str = "EvePulse", device_product: str = "NetWatch", device_version: str = "0.3.0") -> str:
    """
    Exports alerts in Common Event Format (CEF) for SIEM ingest (Splunk, Elastic, QRadar).
    CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
    """
    cef_lines = []
    severity_map = {"HIGH": "8", "MEDIUM": "5", "LOW": "2"}
    for a in alerts:
        sev_num = severity_map.get(a.get("severity", "LOW"), "1")
        name = a.get("reasons") or "Network Behavior Alert"
        ext = f"src={a.get('src_ip', '')} cs1={a.get('domain', '')} cs1Label=Domain cn1={a.get('score', 0)} cn1Label=RiskScore msg={a.get('details', '')}"
        line = f"CEF:0|{device_vendor}|{device_product}|{device_version}|1001|{name}|{sev_num}|{ext}"
        cef_lines.append(line)
    return "\n".join(cef_lines)


def export_to_markdown_report(stats: Dict[str, Any], alerts: List[Dict[str, Any]]) -> str:
    """Generates an executive incident summary in GitHub-Flavored Markdown."""
    lines = [
        "# EvePulse Defensive Security Audit Report",
        f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
        "",
        "## Summary Metrics",
        f"- **Total Events Processed:** {stats.get('total_events', 0)}",
        f"- **Total Security Alerts:** {stats.get('total_alerts', 0)}",
        f"- **High Severity Incidents:** {stats.get('severity_counts', {}).get('HIGH', 0)}",
        f"- **Medium Severity Incidents:** {stats.get('severity_counts', {}).get('MEDIUM', 0)}",
        f"- **Low Severity Incidents:** {stats.get('severity_counts', {}).get('LOW', 0)}",
        "",
        "## Recent Alerts",
        "| ID | Timestamp | Severity | Score | Source IP | Target Domain | Reasons |",
        "|---|---|---|---|---|---|---|",
    ]
    for a in alerts[:25]:
        ts = time.strftime('%H:%M:%S', time.gmtime(a.get("timestamp", 0)))
        lines.append(f"| {a.get('id', '-')} | {ts} | {a.get('severity')} | {a.get('score')} | `{a.get('src_ip')}` | `{a.get('domain') or '-'}` | {a.get('reasons')} |")

    return "\n".join(lines)
