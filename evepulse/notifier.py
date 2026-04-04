"""
Notification and Alert Dispatcher for EvePulse
Supports sending critical alerts to Discord, Slack, or generic webhook receivers.
"""

import json
import logging
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

logger = logging.getLogger("evepulse.notifier")


class AlertNotifier:
    """Dispatches real-time security alerts to external incident management channels."""

    def __init__(self, webhook_url: Optional[str] = None, min_severity: str = "MEDIUM"):
        self.webhook_url = webhook_url
        self.min_severity = min_severity
        self.severity_ranks = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

    def should_notify(self, severity: str) -> bool:
        if not self.webhook_url:
            return False
        return self.severity_ranks.get(severity, 1) >= self.severity_ranks.get(self.min_severity, 2)

    def dispatch(self, alert: Dict[str, Any]) -> bool:
        if not self.should_notify(alert.get("severity", "LOW")):
            return False

        # Format payload (compatible with Discord, Slack, and generic webhooks)
        src = alert.get("src_ip", "Unknown")
        domain = alert.get("domain", "Unknown")
        sev = alert.get("severity", "LOW")
        score = alert.get("score", 0)
        reasons = alert.get("reasons", "")

        color = 0x00FF00 if sev == "LOW" else (0xFFA500 if sev == "MEDIUM" else 0xFF0000)
        payload = {
            "content": f"🚨 **[{sev} ALERT]** Suspicious Network Activity Detected from `{src}`",
            "embeds": [
                {
                    "title": f"EvePulse Threat Alert: {sev} (Score: {score})",
                    "color": color,
                    "fields": [
                        {"name": "Source IP", "value": src, "inline": True},
                        {"name": "Target Domain", "value": domain or "N/A", "inline": True},
                        {"name": "Severity", "value": sev, "inline": True},
                        {"name": "Risk Score", "value": str(score), "inline": True},
                        {"name": "Indicators", "value": reasons, "inline": False},
                    ],
                }
            ],
            "text": f"[{sev}] EvePulse Alert: {src} -> {domain} ({reasons}) - Score: {score}",
        }

        try:
            req = urllib.request.Request(
                self.webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "EvePulse-Monitor/0.3.0"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status in (200, 204)
        except Exception as e:
            logger.warning(f"Failed to dispatch alert webhook: {e}")
            return False
