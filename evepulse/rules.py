"""
Rules Engine & Threat Configuration for EvePulse
Loads custom behavioral rules, keyword categories, and IP/subnet whitelists.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Set


DEFAULT_CONFIG = {
    "thresholds": {
        "burst_events": 12,
        "burst_domains": 6,
        "burst_window_seconds": 60,
        "auth_event_threshold": 8,
        "low_cutoff": 4,
        "medium_cutoff": 9,
    },
    "scores": {
        "ioc_domain": 6,
        "auth_keyword": 2,
        "burst_anomaly": 5,
        "auth_burst": 3,
        "suricata_alert": 10,
    },
    "whitelisted_ips": [
        "127.0.0.1",
        "::1",
    ],
    "custom_keywords": [
        "otp", "verify", "verification", "one-time", "one_time",
        "sms", "call", "login", "register", "authenticate", "auth",
        "password", "passcode", "code", "mfa", "2fa", "token"
    ],
}


class RuleConfig:
    def __init__(self, config_path: str = "rules/custom_rules.json"):
        self.config_path = Path(config_path)
        self.config = self._load()

    def _load(self) -> Dict[str, Any]:
        if self.config_path.exists():
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    cfg = DEFAULT_CONFIG.copy()
                    cfg.update(data)
                    return cfg
            except Exception:
                pass
        return DEFAULT_CONFIG.copy()

    def save_default_if_missing(self):
        if not self.config_path.exists():
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(DEFAULT_CONFIG, f, indent=2)

    @property
    def thresholds(self) -> Dict[str, int]:
        return self.config.get("thresholds", DEFAULT_CONFIG["thresholds"])

    @property
    def scores(self) -> Dict[str, int]:
        return self.config.get("scores", DEFAULT_CONFIG["scores"])

    @property
    def keywords(self) -> Set[str]:
        return set(self.config.get("custom_keywords", DEFAULT_CONFIG["custom_keywords"]))

    @property
    def whitelisted_ips(self) -> Set[str]:
        return set(self.config.get("whitelisted_ips", DEFAULT_CONFIG["whitelisted_ips"]))
